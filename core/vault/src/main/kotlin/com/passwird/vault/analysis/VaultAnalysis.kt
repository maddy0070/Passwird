package com.passwird.vault.analysis

import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.vault.strength.StrengthEstimate
import com.passwird.vault.strength.StrengthEstimator
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * Security findings for a vault.
 *
 * Deliberately **counts, never a score.** "3 reused, 1 weak, 12 older than two years" is
 * actionable; "Security Score: 78" is decorative — it compresses unrelated risks into one
 * number that cannot be acted on and that mostly serves to make people feel judged. See
 * `docs/01-product-spec.md` §7.
 */
data class SecurityFindings(
    val weak: List<Finding>,
    val reused: List<ReuseGroup>,
    val ageing: List<Finding>,
    val totalChecked: Int,
) {
    val hasFindings: Boolean get() = weak.isNotEmpty() || reused.isNotEmpty() || ageing.isNotEmpty()

    /** The single quiet number the Security tab badge shows. */
    val actionableCount: Int get() = weak.size + reused.sumOf { it.itemIds.size } + ageing.size
}

data class Finding(
    val itemId: UUID,
    val title: String,
    val strength: StrengthEstimate? = null,
    val ageDays: Long? = null,
)

/** Items sharing one password. The group is the finding — a single item cannot be "reused". */
data class ReuseGroup(val itemIds: List<UUID>, val titles: List<String>)

object VaultAnalyser {

    /** Below this, a password is worth replacing even if nothing else is wrong with it. */
    const val WEAK_THRESHOLD_BITS: Double = 45.0

    /** Password age at which rotation is worth *suggesting* — never demanding. */
    val AGEING_THRESHOLD: Duration = Duration.ofDays(365 * 2)

    fun analyse(document: VaultDocument, now: Instant): SecurityFindings {
        val items = document.liveItems()
        val withPasswords = items.mapNotNull { item -> passwordOf(item)?.let { item to it } }

        val weak = mutableListOf<Finding>()
        val ageing = mutableListOf<Finding>()

        for ((item, password) in withPasswords) {
            if (password.isEmpty) continue

            val estimate = StrengthEstimator.estimate(password.reveal())
            if (estimate.entropyBits < WEAK_THRESHOLD_BITS) {
                weak += Finding(item.id, item.title, strength = estimate)
            }

            passwordUpdatedAt(item)?.let { updatedAt ->
                val age = Duration.between(updatedAt, now)
                if (age > AGEING_THRESHOLD) {
                    ageing += Finding(item.id, item.title, ageDays = age.toDays())
                }
            }
        }

        return SecurityFindings(
            weak = weak.sortedBy { it.strength?.entropyBits ?: 0.0 },
            reused = findReuse(withPasswords),
            ageing = ageing.sortedByDescending { it.ageDays },
            totalChecked = withPasswords.size,
        )
    }

    /**
     * Groups items sharing a password.
     *
     * Comparison happens **in memory only**, and nothing derived from it is ever
     * persisted. A stored table of password hashes would be a second, weaker copy of the
     * vault's most sensitive content — and one that outlives the session. Recomputing on
     * demand costs microseconds and removes that artefact entirely.
     */
    private fun findReuse(withPasswords: List<Pair<VaultItem, Secret>>): List<ReuseGroup> =
        withPasswords
            .filterNot { (_, password) -> password.isEmpty }
            .groupBy({ (_, password) -> password }, { (item, _) -> item })
            .values
            .filter { it.size > 1 }
            .map { group -> ReuseGroup(group.map { it.id }, group.map { it.title }) }
            .sortedByDescending { it.itemIds.size }

    /** The password-bearing field of any item type that has one. */
    fun passwordOf(item: VaultItem): Secret? = when (val content = item.content) {
        is ItemContent.Login -> content.password
        is ItemContent.WifiCredential -> content.password
        is ItemContent.DatabaseCredential -> content.password
        is ItemContent.ApiKey -> content.secret
        is ItemContent.SshCredential -> content.privateKey.takeIf { !it.isEmpty }
        else -> null
    }

    /**
     * When the *password* last changed, not the record.
     *
     * Falling back to `updatedAt` would make editing a note reset the rotation clock and
     * turn the ageing report into noise, so items that have never recorded a password
     * change are simply excluded rather than guessed at.
     */
    private fun passwordUpdatedAt(item: VaultItem): Instant? = when (val content = item.content) {
        is ItemContent.Login -> content.passwordUpdatedAt
        else -> null
    }
}
