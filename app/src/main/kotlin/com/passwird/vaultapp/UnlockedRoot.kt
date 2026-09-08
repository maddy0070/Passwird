package com.passwird.vaultapp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.passwird.design.components.SyncStatus
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultItem
import com.passwird.platform.secure.ClipboardGuard
import com.passwird.sync.SyncOutcome
import com.passwird.vault.generator.PasswordGenerator
import com.passwird.vault.generator.PasswordPolicy
import com.passwird.vault.strength.AttackRates
import com.passwird.vault.strength.CrackTimeFormatter
import com.passwird.vault.strength.StrengthEstimator
import com.passwird.vaultapp.ui.HomeScreen
import com.passwird.vaultapp.ui.ItemDetailScreen
import com.passwird.vaultapp.ui.ItemDraft
import com.passwird.vaultapp.ui.ItemEditorScreen
import java.util.UUID
import kotlinx.coroutines.launch

/** Where the user is inside the unlocked vault. */
private sealed interface Route {
    data object Home : Route
    data class Detail(val id: UUID) : Route
    data class Edit(val id: UUID?) : Route
}

/**
 * Everything reachable once the vault is open.
 *
 * Composed only in the `Unlocked` branch of the vault state machine, so a locked or absent
 * vault has no rendered screen that could hold a credential — the boundary is structural, not
 * a guard clause a future navigation change could route around.
 *
 * Navigation is a `when` over a local route rather than a nav library: three destinations, no
 * deep links, and a back stack that must be *forgotten* on lock rather than restored. A
 * library that helpfully preserved state across a lock would be working against the product.
 */
@Composable
fun UnlockedRoot(
    container: PasswirdContainer,
    modifier: Modifier = Modifier,
    onLock: () -> Unit = {},
    onEnrolBiometrics: (() -> Unit)? = null,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val repository = container.repository

    val document by repository.vault.collectAsState()
    val syncOutcome by repository.syncStatus.collectAsState()

    val clipboard = remember(scope) { ClipboardGuard(context, scope) }
    val clipboardSeconds by clipboard.secondsRemaining.collectAsState()

    var route by remember { mutableStateOf<Route>(Route.Home) }
    var query by remember { mutableStateOf("") }
    var draft by remember { mutableStateOf(ItemDraft()) }

    val items = document?.liveItems().orEmpty()
    val results = remember(query, items) {
        if (query.isBlank()) {
            items
        } else {
            val byId = items.associateBy { it.id }
            repository.search(query).mapNotNull { byId[it.itemId] }.distinct()
        }
    }

    fun copy(value: String, label: String, sensitive: Boolean) {
        if (sensitive) {
            clipboard.copySensitive(value, label, CLIPBOARD_CLEAR_SECONDS)
        } else {
            clipboard.copyPlain(value, label)
        }
    }

    when (val current = route) {
        is Route.Home -> HomeScreen(
            modifier = modifier,
            query = query,
            onQueryChange = { query = it },
            results = results,
            recents = repository.recent(),
            totalCount = items.size,
            syncStatus = syncOutcome.toStatus(),
            pendingChanges = 0,
            onOpenItem = { id ->
                scope.launch { repository.markUsed(id) }
                route = Route.Detail(id)
            },
            onCopyPassword = { id ->
                // Copy without opening the item: the critical path in `09-ux-flows.md` §2 is
                // unlock → find → copy, and routing it through a detail screen would add a
                // step to the one journey the product is organised around.
                items.firstOrNull { it.id == id }?.let { item ->
                    item.passwordOrNull()?.let { copy(it, item.title, sensitive = true) }
                }
            },
            onAdd = {
                draft = ItemDraft()
                route = Route.Edit(null)
            },
            onSyncTap = { scope.launch { repository.sync() } },
            onLock = onLock,
            onEnrolBiometrics = onEnrolBiometrics,
        )

        is Route.Detail -> {
            val item = items.firstOrNull { it.id == current.id }
            if (item == null) {
                // The item was deleted underneath us — by an undo, a merge, or a sync.
                route = Route.Home
            } else {
                val password = item.passwordOrNull().orEmpty()
                val strength = remember(password) { StrengthEstimator.estimate(password) }
                val crackSeconds = strength.secondsToCrack(AttackRates.OFFLINE_ARGON2ID)

                ItemDetailScreen(
                    modifier = modifier,
                    item = item,
                    strengthBits = strength.entropyBits,
                    crackTime = CrackTimeFormatter.describe(crackSeconds),
                    // The rate is named, never implied. A strength claim without a stated
                    // attacker model is meaningless, which is why the estimator refuses to
                    // hide it behind a default.
                    attackRate = "offline attack against this vault's Argon2id parameters",
                    weaknesses = strength.weaknesses.map { it.detail },
                    passwordAgeDescription = null,
                    clipboardSecondsRemaining = clipboardSeconds,
                    onBack = { route = Route.Home },
                    onEdit = {
                        draft = item.toDraft()
                        route = Route.Edit(item.id)
                    },
                    onToggleFavourite = {
                        scope.launch { repository.upsert(item.copy(favorite = !item.favorite)) }
                    },
                    // A username is not a secret, so it does not get the auto-clearing
                    // treatment a password does. Treating them identically would train users
                    // to ignore the countdown that matters.
                    onCopyUsername = {
                        item.usernameOrNull()?.let { copy(it, "${item.title} username", sensitive = false) }
                    },
                    onCopyPassword = {
                        item.passwordOrNull()?.let { copy(it, item.title, sensitive = true) }
                    },
                    onOpenWebsite = { },
                    onDelete = {
                        scope.launch { repository.delete(item.id) }
                        route = Route.Home
                    },
                )
            }
        }

        is Route.Edit -> {
            val existing = current.id?.let { id -> items.firstOrNull { it.id == id } }
            ItemEditorScreen(
                modifier = modifier,
                draft = draft,
                isNew = existing == null,
                onDraftChange = { draft = it },
                onGeneratePassword = {
                    draft = draft.copy(
                        password = PasswordGenerator.generate(PasswordPolicy()).value.reveal(),
                    )
                },
                onSave = {
                    scope.launch {
                        repository.upsert(draft.toItem(existing, container.repository))
                        route = existing?.let { Route.Detail(it.id) } ?: Route.Home
                    }
                },
                onCancel = {
                    route = existing?.let { Route.Detail(it.id) } ?: Route.Home
                },
                onDelete = existing?.let { item ->
                    {
                        scope.launch { repository.delete(item.id) }
                        route = Route.Home
                    }
                },
            )
        }
    }
}

private fun VaultItem.passwordOrNull(): String? =
    (content as? ItemContent.Login)?.password?.reveal()

private fun VaultItem.usernameOrNull(): String? =
    (content as? ItemContent.Login)?.username?.takeIf { it.isNotBlank() }

private fun VaultItem.toDraft(): ItemDraft {
    val login = content as? ItemContent.Login
    return ItemDraft(
        title = title,
        username = login?.username.orEmpty(),
        password = login?.password?.reveal().orEmpty(),
        website = login?.urls?.firstOrNull().orEmpty(),
        notes = notes,
    )
}

/**
 * Builds the domain item from the draft.
 *
 * Preserves the existing record's identity and timestamps where there is one, so an edit stays
 * an edit: a new id would look like a delete plus a create to the merge algorithm, and would
 * resurrect on another device as a duplicate.
 */
private fun ItemDraft.toItem(existing: VaultItem?, repository: com.passwird.store.VaultRepository): VaultItem {
    val now = java.time.Instant.now()
    val login = ItemContent.Login(
        username = username,
        password = Secret.of(password),
        urls = listOfNotNull(website.takeIf { it.isNotBlank() }),
    )
    return existing?.copy(title = title, content = login, notes = notes)
        ?: VaultItem(
            id = UUID.randomUUID(),
            title = title,
            content = login,
            notes = notes,
            createdAt = now,
            updatedAt = now,
            // Overwritten by the repository, which owns this device's identity.
            originDeviceId = com.passwird.model.DeviceId("pending"),
        )
}

private fun SyncOutcome?.toStatus(): SyncStatus = when (this) {
    null -> SyncStatus.OFFLINE
    is SyncOutcome.UpToDate, is SyncOutcome.Uploaded -> SyncStatus.SYNCED
    is SyncOutcome.Downloaded -> SyncStatus.SYNCED
    is SyncOutcome.Merged -> SyncStatus.NEEDS_REVIEW
    is SyncOutcome.Offline -> SyncStatus.OFFLINE
    is SyncOutcome.Failed -> SyncStatus.FAILED
    else -> SyncStatus.OFFLINE
}

private const val CLIPBOARD_CLEAR_SECONDS = 45
