package com.passwird.design.tokens

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * A 4dp base grid. Nothing in the product sits off this scale.
 *
 * The lint gate in CI rejects any `dp` literal in UI code that is not one of these, which
 * is the difference between a design system and a set of suggestions.
 */
@Immutable
data class PasswirdSpacing(
    val xxs: Dp = 2.dp,
    val xs: Dp = 4.dp,
    val s: Dp = 8.dp,
    val sm: Dp = 12.dp,
    val m: Dp = 16.dp,
    val ml: Dp = 20.dp,
    val l: Dp = 24.dp,
    val xl: Dp = 32.dp,
    val xxl: Dp = 40.dp,
    val xxxl: Dp = 48.dp,
    val huge: Dp = 64.dp,

    /** Screen horizontal margin. */
    val gutter: Dp = 20.dp,
    /** List row vertical padding. */
    val rowV: Dp = 14.dp,
    val sectionGap: Dp = 32.dp,
    val fieldGap: Dp = 16.dp,

    /**
     * Minimum touch target, always.
     *
     * Applies especially to the reveal and copy controls, which are chronically undersized
     * across this product category.
     */
    val touchMin: Dp = 48.dp,

    /** The shared row template: icon column, gap, content, trailing affordance. */
    val rowIconColumn: Dp = 40.dp,
    val rowIconGap: Dp = 12.dp,
    val rowTrailing: Dp = 48.dp,
)

/**
 * Near-square geometry, and one radius for interactive surfaces.
 *
 * The most visible break from category convention, and deliberate: squared edges read as
 * precise and built, while 16dp-rounded everything reads as soft and generic. A pill shape
 * appears exactly once in the product, on the sync indicator, so that it is unmistakably
 * *the* status element.
 */
@Immutable
data class PasswirdShapes(
    /** Structural containers, sections, list rows. */
    val none: Shape = RoundedCornerShape(0.dp),
    /** Buttons, inputs, chips, menus. */
    val small: Shape = RoundedCornerShape(4.dp),
    /** Dialogs. */
    val medium: Shape = RoundedCornerShape(8.dp),
    /** Bottom sheets — top corners only. */
    val sheet: Shape = RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp),
    /** The sync indicator, and nothing else. */
    val pill: Shape = RoundedCornerShape(percent = 50),

    val hairline: Dp = 1.dp,
    val focusRingWidth: Dp = 2.dp,
)

/**
 * Elevation.
 *
 * **Dark theme has no shadows.** Depth comes from surface luminance plus a hairline;
 * shadows on near-black are muddy and read as smudges rather than as height. Light theme
 * uses a single soft shadow, for sheets and dialogs only.
 */
@Immutable
data class PasswirdElevation(
    val flat: Dp = 0.dp,
    val raised: Dp = 0.dp,
    /** Light theme only — zeroed in dark by the theme. */
    val sheet: Dp = 8.dp,
    val dialog: Dp = 12.dp,
)
