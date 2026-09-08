package com.passwird.design.tokens

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Immutable

/**
 * Motion tokens.
 *
 * **Every animation reports a state change. Nothing moves for pleasure.** If a motion
 * cannot be justified by what it tells the user, it does not ship.
 *
 * The budget is deliberately lopsided: one signature moment at 420ms, and everything else
 * as functional feedback between 120 and 260ms. Spending the identity in one place is what
 * keeps the rest of the product feeling instant.
 */
@Immutable
data class PasswirdMotion(
    /**
     * Reveal and mask toggles.
     *
     * Zero, on purpose. A password appearing should feel like a switch being thrown, not
     * like something fading in — and a fade means there is a moment where the password is
     * half-legible, which is neither secure nor satisfying.
     */
    val instant: Int = 0,
    val quick: Int = 120,
    val base: Int = 180,
    val considered: Int = 260,
    /** Unlock and lock. The only place this duration is used. */
    val deliberate: Int = 420,
    val exit: Int = 140,

    val standard: Easing = CubicBezierEasing(0.2f, 0f, 0f, 1f),
    val mechanism: Easing = CubicBezierEasing(0.35f, 0f, 0.15f, 1f),
    val accelerate: Easing = CubicBezierEasing(0.4f, 0f, 1f, 1f),

    /** Stagger between the first few vault rows after unlock. */
    val staggerStepMillis: Int = 60,
    val staggerMaxRows: Int = 6,

    /**
     * When true, every transition collapses to a plain opacity crossfade.
     *
     * Reduced motion removes *movement*, never *information*: unlock still confirms, via an
     * instant state change plus a haptic tick.
     */
    val reduceMotion: Boolean = false,
) {
    fun <T> spec(durationMillis: Int, easing: Easing = standard): FiniteAnimationSpec<T> =
        if (reduceMotion) {
            tween(durationMillis = REDUCED_MOTION_MILLIS, easing = standard)
        } else {
            tween(durationMillis = durationMillis, easing = easing)
        }

    fun staggerDelayFor(index: Int): Int =
        if (reduceMotion) 0 else (index.coerceAtMost(staggerMaxRows) * staggerStepMillis)

    companion object {
        const val REDUCED_MOTION_MILLIS = 100
    }
}
