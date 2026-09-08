package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.passwird.design.components.EmptyState
import com.passwird.design.components.GeneratedMarkView
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.ItemRow
import com.passwird.design.components.ItemTypeGlyph
import com.passwird.design.components.PasswirdIconButton
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SearchField
import com.passwird.design.components.SecurityBadge
import com.passwird.design.components.BadgeTone
import com.passwird.design.components.Section
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.SyncIndicator
import com.passwird.design.components.SyncStatus
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.model.ItemContent
import com.passwird.model.ItemType
import com.passwird.model.VaultItem
import java.util.UUID

/**
 * The home screen: a **retrieval surface, not a dashboard**.
 *
 * Job 1 — find a credential fast, usually one-handed, often under mild stress — outnumbers
 * every other job by roughly an order of magnitude, so search sits first under the thumb
 * and everything else earns its place beneath it.
 *
 * Two decisions that follow from the 4-second critical path:
 *
 * **Copy is available from the row.** The user does not have to open an item to get its
 * password. This is the single largest time saving in the flow, and most competitors do
 * not do it.
 *
 * **Recents appear only when genuinely recent**, capped at four. Most people re-use a small
 * set of credentials, so a short strip removes a search interaction for the majority of
 * retrievals — and showing an empty box when there is nothing recent would be worse than
 * showing nothing.
 *
 * There is deliberately no security dashboard here. Opening a password manager to a wall of
 * warnings is hostile at exactly the moment the user wanted one credential in nine seconds;
 * findings live in the Security tab as a quiet count.
 */
@Composable
fun HomeScreen(
    query: String,
    onQueryChange: (String) -> Unit,
    results: List<VaultItem>,
    recents: List<VaultItem>,
    totalCount: Int,
    syncStatus: SyncStatus,
    pendingChanges: Int,
    onOpenItem: (UUID) -> Unit,
    onCopyPassword: (UUID) -> Unit,
    onAdd: () -> Unit,
    onSyncTap: () -> Unit,
    modifier: Modifier = Modifier,
    /** Locks the vault immediately. Always reachable — a user who wants to lock cannot wait. */
    onLock: () -> Unit = {},
    /**
     * Offered only when the device has Class 3 biometric hardware and this vault is not yet
     * enrolled. Null hides the control entirely rather than showing a disabled one: an
     * affordance that cannot work is worse than no affordance in a security product.
     */
    onEnrolBiometrics: (() -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val searching = query.isNotBlank()

    Box(modifier = modifier.fillMaxSize().background(colors.ground)) {
        LazyColumn(modifier = Modifier.fillMaxSize()) {

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = spacing.gutter)
                        .padding(top = spacing.m, bottom = spacing.s),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(spacing.s),
                ) {
                    SearchField(
                        query = query,
                        onQueryChange = onQueryChange,
                        modifier = Modifier.weight(1f),
                    )
                    // Always visible, never behind a menu. A user who has decided to lock
                    // their vault is usually reacting to something, and making them hunt for
                    // it is the one delay this control must never impose.
                    PasswirdIconButton(
                        icon = PasswirdIcons.Locked,
                        contentDescription = "Lock vault now",
                        onClick = onLock,
                    )
                }
                if (onEnrolBiometrics != null) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = spacing.gutter)
                            .padding(bottom = spacing.s),
                    ) {
                        SecondaryButton(
                            text = "Turn on fingerprint unlock",
                            onClick = onEnrolBiometrics,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = spacing.gutter, vertical = spacing.xs),
                    horizontalArrangement = Arrangement.End,
                ) {
                    SyncIndicator(
                        status = syncStatus,
                        pendingChanges = pendingChanges,
                        onClick = onSyncTap,
                    )
                }
                Spacer(Modifier.height(spacing.s))
            }

            if (searching) {
                if (results.isEmpty()) {
                    item {
                        EmptyState(
                            title = "No matches for “$query”",
                            body = "Nothing in your vault matches that yet.",
                            icon = PasswirdIcons.Search,
                            action = { PrimaryButton("Create a login called “$query”", onAdd) },
                        )
                    }
                } else {
                    items(results, key = { it.id }) { item ->
                        VaultItemRow(item, onOpenItem, onCopyPassword)
                        HairlineDivider(inset = true)
                    }
                }
            } else {
                if (totalCount == 0) {
                    item {
                        EmptyState(
                            title = "Nothing here yet",
                            body = "Add your first credential, or generate a password to get started.",
                            icon = PasswirdIcons.Locked,
                            action = { PrimaryButton("Add a credential", onAdd) },
                        )
                    }
                } else {
                    if (recents.isNotEmpty()) {
                        item { Section(label = "Recent") { } }
                        items(recents, key = { "recent-${it.id}" }) { item ->
                            VaultItemRow(item, onOpenItem, onCopyPassword)
                            HairlineDivider(inset = true)
                        }
                    }

                    item {
                        Section(
                            label = "All items",
                            trailing = {
                                Text(
                                    text = totalCount.toString(),
                                    // Tabular figures, so the count does not shift the label
                                    // as items are added.
                                    style = PasswirdTheme.typography.numeric,
                                    color = colors.textTertiary,
                                )
                            },
                        ) { }
                    }
                    items(results, key = { it.id }) { item ->
                        VaultItemRow(item, onOpenItem, onCopyPassword)
                        HairlineDivider(inset = true)
                    }
                }
            }

            item { Spacer(Modifier.height(96.dp)) }
        }

        PrimaryButton(
            text = "Add",
            icon = PasswirdIcons.Add,
            onClick = onAdd,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(spacing.gutter),
        )
    }
}

@Composable
private fun VaultItemRow(
    item: VaultItem,
    onOpen: (UUID) -> Unit,
    onCopyPassword: (UUID) -> Unit,
) {
    val hasPassword = item.content is ItemContent.Login ||
        item.content is ItemContent.WifiCredential ||
        item.content is ItemContent.DatabaseCredential

    ItemRow(
        title = item.title,
        subtitle = subtitleFor(item),
        onClick = { onOpen(item.id) },
        leading = {
            val domain = (item.content as? ItemContent.Login)?.urls?.firstOrNull()
            if (domain != null) {
                GeneratedMarkView(source = domain)
            } else {
                ItemTypeGlyph(icon = glyphFor(item.type))
            }
        },
        badge = {
            if (item.needsReview) {
                SecurityBadge(text = "Review", tone = BadgeTone.ATTENTION)
            }
        },
        trailing = {
            if (hasPassword) {
                // Copying without opening the item is what keeps retrieval inside four
                // seconds.
                PasswirdIconButton(
                    icon = PasswirdIcons.Copy,
                    contentDescription = "Copy password for ${item.title}",
                    onClick = { onCopyPassword(item.id) },
                )
            }
        },
    )
}

private fun subtitleFor(item: VaultItem): String? = when (val content = item.content) {
    is ItemContent.Login -> content.username.ifBlank { content.email }
    is ItemContent.ApiKey -> content.service
    is ItemContent.WifiCredential -> content.ssid
    is ItemContent.PaymentCard -> content.cardholder.ifBlank { null }
    is ItemContent.DatabaseCredential -> content.host
    is ItemContent.SshCredential -> content.host
    is ItemContent.RecoveryCodes -> "${content.remaining} unused"
    is ItemContent.SoftwareLicense -> content.product
    is ItemContent.Identity -> content.fullName
    is ItemContent.SecureNote -> null
    is ItemContent.Custom -> content.typeName
}

private fun glyphFor(type: ItemType) = when (type) {
    ItemType.SECURE_NOTE -> PasswirdIcons.Edit
    ItemType.PAYMENT_CARD -> PasswirdIcons.Copy
    ItemType.WIFI -> PasswirdIcons.Offline
    ItemType.SSH, ItemType.API_KEY, ItemType.DATABASE -> PasswirdIcons.Generate
    ItemType.RECOVERY_CODES -> PasswirdIcons.Shield
    else -> PasswirdIcons.Locked
}
