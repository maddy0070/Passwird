package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.PasswirdIconButton
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.PasswirdToggle
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.ScreenHeader
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.SegmentedControl
import com.passwird.design.components.Stepper
import com.passwird.design.components.StrengthReadout
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.vault.generator.CharClass
import com.passwird.vault.generator.PassphrasePolicy
import com.passwird.vault.generator.PasswordPolicy

/**
 * The generator.
 *
 * Top-level rather than buried in the editor, because people need a password for something
 * they are signing up for *in another app* at least as often as while saving an item here.
 *
 * The entropy shown for a generated password is **exact**, not estimated — we sampled the
 * distribution, so we know it. The readout says so, and states the attack rate it assumes,
 * because a strength number without an attacker model means nothing.
 *
 * Note what the passphrase options do *not* claim: capitalising every word adds zero bits,
 * since the rule is deterministic and an attacker knows it. We offer it because people like
 * it, and we decline to credit it. Adding a digit is credited with the 5.6 bits it actually
 * contributes, and no more.
 */
@Composable
fun GeneratorScreen(
    mode: GeneratorMode,
    onModeChange: (GeneratorMode) -> Unit,
    generated: String,
    entropyBits: Double,
    crackTime: String,
    attackRate: String,
    passwordPolicy: PasswordPolicy,
    onPasswordPolicyChange: (PasswordPolicy) -> Unit,
    passphrasePolicy: PassphrasePolicy,
    onPassphrasePolicyChange: (PassphrasePolicy) -> Unit,
    onRegenerate: () -> Unit,
    onCopy: () -> Unit,
    onUse: (() -> Unit)?,
    onBack: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground),
    ) {
        ScreenHeader(title = "Generate", onBack = onBack)

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
        ) {
            Column(Modifier.padding(spacing.gutter)) {
                SegmentedControl(
                    options = listOf("Password", "Passphrase"),
                    selectedIndex = if (mode == GeneratorMode.PASSWORD) 0 else 1,
                    onSelect = { onModeChange(if (it == 0) GeneratorMode.PASSWORD else GeneratorMode.PASSPHRASE) },
                )

                Spacer(Modifier.height(spacing.l))

                // The result, in mono so it can be read aloud and transcribed reliably.
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(
                        text = generated,
                        style = PasswirdTheme.typography.mono,
                        color = colors.textPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    PasswirdIconButton(PasswirdIcons.Generate, "Generate another", onRegenerate)
                    PasswirdIconButton(PasswirdIcons.Copy, "Copy generated value", onCopy)
                }

                Spacer(Modifier.height(spacing.m))

                StrengthReadout(
                    entropyBits = entropyBits,
                    // Exact: we know the distribution we drew from.
                    isExact = true,
                    crackTimeDescription = crackTime,
                    attackRateDescription = attackRate,
                )
            }

            HairlineDivider()
            Spacer(Modifier.height(spacing.s))

            when (mode) {
                GeneratorMode.PASSWORD -> PasswordOptions(passwordPolicy, onPasswordPolicyChange)
                GeneratorMode.PASSPHRASE -> PassphraseOptions(passphrasePolicy, onPassphrasePolicyChange)
            }

            Spacer(Modifier.height(spacing.xl))
        }

        HairlineDivider()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(spacing.gutter),
            horizontalArrangement = Arrangement.spacedBy(spacing.s),
        ) {
            SecondaryButton("Copy", onCopy, modifier = Modifier.weight(1f))
            onUse?.let { PrimaryButton("Use this", it, modifier = Modifier.weight(1f)) }
        }
    }
}

enum class GeneratorMode { PASSWORD, PASSPHRASE }

@Composable
private fun PasswordOptions(
    policy: PasswordPolicy,
    onChange: (PasswordPolicy) -> Unit,
) {
    val spacing = PasswirdTheme.spacing

    Column(Modifier.padding(horizontal = spacing.gutter)) {
        Stepper(
            value = policy.length,
            onValueChange = { onChange(policy.copy(length = it)) },
            label = "Length",
            range = PasswordPolicy.MIN_LENGTH..64,
        )
    }

    fun toggleClass(charClass: CharClass, enabled: Boolean) {
        val next = if (enabled) policy.classes + charClass else policy.classes - charClass
        // A policy with no classes cannot generate anything, so the last one is sticky
        // rather than producing an error the user has to resolve.
        if (next.isNotEmpty()) onChange(policy.copy(classes = next))
    }

    PasswirdToggle(
        checked = CharClass.UPPERCASE in policy.classes,
        onCheckedChange = { toggleClass(CharClass.UPPERCASE, it) },
        label = "Uppercase",
        description = "A – Z",
    )
    PasswirdToggle(
        checked = CharClass.LOWERCASE in policy.classes,
        onCheckedChange = { toggleClass(CharClass.LOWERCASE, it) },
        label = "Lowercase",
        description = "a – z",
    )
    PasswirdToggle(
        checked = CharClass.DIGITS in policy.classes,
        onCheckedChange = { toggleClass(CharClass.DIGITS, it) },
        label = "Numbers",
        description = "0 – 9",
    )
    PasswirdToggle(
        checked = CharClass.SYMBOLS in policy.classes,
        onCheckedChange = { toggleClass(CharClass.SYMBOLS, it) },
        label = "Symbols",
        description = "! # $ % & …",
    )
    PasswirdToggle(
        checked = policy.excludeAmbiguous,
        onCheckedChange = { onChange(policy.copy(excludeAmbiguous = it)) },
        label = "Avoid look-alike characters",
        description = "Leaves out 0 O 1 l I | 5 S — useful when you'll read it aloud or type it by hand",
    )
    PasswirdToggle(
        checked = policy.requireEachClass,
        onCheckedChange = { onChange(policy.copy(requireEachClass = it)) },
        label = "Use every selected type",
        description = "Guarantees at least one of each. Slightly reduces the number of possible passwords, and the figure above accounts for that.",
    )
}

@Composable
private fun PassphraseOptions(
    policy: PassphrasePolicy,
    onChange: (PassphrasePolicy) -> Unit,
) {
    val spacing = PasswirdTheme.spacing

    Column(Modifier.padding(horizontal = spacing.gutter)) {
        Stepper(
            value = policy.wordCount,
            onValueChange = { onChange(policy.copy(wordCount = it)) },
            label = "Words",
            range = PassphrasePolicy.MIN_WORDS..PassphrasePolicy.MAX_WORDS,
        )
    }

    PasswirdToggle(
        checked = policy.capitalise,
        onCheckedChange = { onChange(policy.copy(capitalise = it)) },
        label = "Capitalise each word",
        // Said plainly rather than quietly credited.
        description = "Looks tidier. Adds no extra security, because the rule is predictable.",
    )
    PasswirdToggle(
        checked = policy.includeNumber,
        onCheckedChange = { onChange(policy.copy(includeNumber = it)) },
        label = "Add a number",
        description = "Adds about 5.6 bits — some sites insist on a digit.",
    )
}
