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
import com.passwird.model.VaultItem
import com.passwird.platform.secure.ClipboardGuard
import com.passwird.sync.SyncOutcome
import com.passwird.vaultapp.ui.HomeScreen
import kotlinx.coroutines.launch

/**
 * Everything reachable once the vault is open.
 *
 * Composed only while `repository.vault` is non-null, so a locked vault has no rendered
 * screen that could hold a credential — the lock boundary is structural, not a guard clause
 * that a future navigation change could route around.
 */
@Composable
fun UnlockedRoot(
    container: PasswirdContainer,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val repository = container.repository

    val document by repository.vault.collectAsState()
    val syncOutcome by repository.syncStatus.collectAsState()

    val clipboard = remember(scope) { ClipboardGuard(context, scope) }
    var query by remember { mutableStateOf("") }

    val items = document?.liveItems().orEmpty()
    val results = remember(query, items) {
        if (query.isBlank()) {
            items
        } else {
            val byId = items.associateBy { it.id }
            repository.search(query).mapNotNull { byId[it.itemId] }.distinct()
        }
    }

    HomeScreen(
        modifier = modifier,
        query = query,
        onQueryChange = { query = it },
        results = results,
        recents = repository.recent(),
        totalCount = items.size,
        syncStatus = syncOutcome.toStatus(),
        pendingChanges = 0,
        onOpenItem = { id -> scope.launch { repository.markUsed(id) } },
        onCopyPassword = { id ->
            // Copy without opening the item: the critical path in `09-ux-flows.md` §2 is
            // unlock → find → copy, and routing it through a detail screen would add a step
            // to the one journey the product is organised around.
            items.firstOrNull { it.id == id }?.let { item ->
                item.passwordOrNull()?.let { password ->
                    clipboard.copySensitive(
                        value = password,
                        label = item.title,
                        clearAfterSeconds = CLIPBOARD_CLEAR_SECONDS,
                    )
                }
            }
        },
        onAdd = { /* The editor is Phase 2 work; see the review's implementation order. */ },
        onSyncTap = { scope.launch { repository.sync() } },
    )
}

/** Reads a login password without widening [ItemContent]'s API to the UI layer. */
private fun VaultItem.passwordOrNull(): String? =
    (content as? ItemContent.Login)?.password?.reveal()

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

