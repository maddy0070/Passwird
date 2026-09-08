package com.passwird.design.components

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * The custom icon set.
 *
 * A single source, drawn on one 24dp grid with a 1.5dp stroke, **square caps and square
 * joins**, and no fills. Squared terminals match the near-square shape language; the more
 * usual round caps would quietly soften every screen and undo the geometry.
 *
 * Drawn rather than imported because a mixed icon set — some Material, some from a pack,
 * some custom — is the fastest way to make a product look unfinished, and it shows up
 * exactly where users look most: the row affordances they tap all day.
 */
object PasswirdIcons {

    private fun icon(name: String, block: androidx.compose.ui.graphics.vector.ImageVector.Builder.() -> Unit) =
        ImageVector.Builder(
            name = name,
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).apply(block).build()

    private fun ImageVector.Builder.stroke(
        pathBuilder: androidx.compose.ui.graphics.vector.PathBuilder.() -> Unit,
    ) = path(
        stroke = SolidColor(Color.Black),
        strokeLineWidth = 1.5f,
        strokeLineCap = StrokeCap.Square,
        strokeLineJoin = StrokeJoin.Miter,
        pathBuilder = pathBuilder,
    )

    val Search: ImageVector = icon("Search") {
        stroke {
            moveTo(11f, 4f); arcToRelative(7f, 7f, 0f, true, true, 0f, 14f)
            arcToRelative(7f, 7f, 0f, true, true, 0f, -14f); close()
        }
        stroke { moveTo(16.2f, 16.2f); lineTo(21f, 21f) }
    }

    val Add: ImageVector = icon("Add") {
        stroke { moveTo(12f, 5f); lineTo(12f, 19f) }
        stroke { moveTo(5f, 12f); lineTo(19f, 12f) }
    }

    val Copy: ImageVector = icon("Copy") {
        stroke { moveTo(9f, 9f); lineTo(20f, 9f); lineTo(20f, 20f); lineTo(9f, 20f); close() }
        stroke { moveTo(15.5f, 5.5f); lineTo(4f, 5.5f); lineTo(4f, 16f) }
    }

    /** Reveal: an open eye. Paired with [Hide], which is the same eye struck through. */
    val Reveal: ImageVector = icon("Reveal") {
        stroke { moveTo(2.5f, 12f); curveTo(5f, 7f, 8.5f, 5f, 12f, 5f); curveTo(15.5f, 5f, 19f, 7f, 21.5f, 12f) }
        stroke { moveTo(21.5f, 12f); curveTo(19f, 17f, 15.5f, 19f, 12f, 19f); curveTo(8.5f, 19f, 5f, 17f, 2.5f, 12f) }
        stroke { moveTo(12f, 9f); arcToRelative(3f, 3f, 0f, true, true, 0f, 6f); arcToRelative(3f, 3f, 0f, true, true, 0f, -6f); close() }
    }

    val Hide: ImageVector = icon("Hide") {
        stroke { moveTo(2.5f, 12f); curveTo(5f, 7f, 8.5f, 5f, 12f, 5f); curveTo(15.5f, 5f, 19f, 7f, 21.5f, 12f) }
        stroke { moveTo(21.5f, 12f); curveTo(19f, 17f, 15.5f, 19f, 12f, 19f); curveTo(8.5f, 19f, 5f, 17f, 2.5f, 12f) }
        stroke { moveTo(4f, 4f); lineTo(20f, 20f) }
    }

    val Locked: ImageVector = icon("Locked") {
        stroke { moveTo(5f, 10.5f); lineTo(19f, 10.5f); lineTo(19f, 20f); lineTo(5f, 20f); close() }
        stroke { moveTo(8f, 10.5f); lineTo(8f, 7.5f); arcToRelative(4f, 4f, 0f, true, true, 8f, 0f); lineTo(16f, 10.5f) }
    }

    val Unlocked: ImageVector = icon("Unlocked") {
        stroke { moveTo(5f, 10.5f); lineTo(19f, 10.5f); lineTo(19f, 20f); lineTo(5f, 20f); close() }
        stroke { moveTo(8f, 10.5f); lineTo(8f, 7.5f); arcToRelative(4f, 4f, 0f, true, true, 8f, 0f) }
    }

    val Star: ImageVector = icon("Star") {
        stroke { moveTo(12f, 4f); lineTo(14.5f, 9.5f); lineTo(20.5f, 10.3f); lineTo(16.2f, 14.5f); lineTo(17.3f, 20.5f); lineTo(12f, 17.6f); lineTo(6.7f, 20.5f); lineTo(7.8f, 14.5f); lineTo(3.5f, 10.3f); lineTo(9.5f, 9.5f); close() }
    }

    val Synced: ImageVector = icon("Synced") {
        stroke { moveTo(5f, 12f); lineTo(10f, 17f); lineTo(19f, 7.5f) }
    }

    val Syncing: ImageVector = icon("Syncing") {
        stroke { moveTo(20f, 12f); arcTo(8f, 8f, 0f, true, true, 12f, 4f) }
        stroke { moveTo(12f, 1.5f); lineTo(12f, 6.5f) }
    }

    val Offline: ImageVector = icon("Offline") {
        stroke { moveTo(4f, 12f); lineTo(20f, 12f) }
        stroke { moveTo(9f, 7.5f); lineTo(4.5f, 12f); lineTo(9f, 16.5f) }
    }

    val Attention: ImageVector = icon("Attention") {
        stroke { moveTo(12f, 3.5f); lineTo(21.5f, 20f); lineTo(2.5f, 20f); close() }
        stroke { moveTo(12f, 10f); lineTo(12f, 14.5f) }
        stroke { moveTo(12f, 17f); lineTo(12f, 17.5f) }
    }

    val Danger: ImageVector = icon("Danger") {
        stroke { moveTo(12f, 3.5f); arcToRelative(8.5f, 8.5f, 0f, true, true, 0f, 17f); arcToRelative(8.5f, 8.5f, 0f, true, true, 0f, -17f); close() }
        stroke { moveTo(8.5f, 8.5f); lineTo(15.5f, 15.5f) }
        stroke { moveTo(15.5f, 8.5f); lineTo(8.5f, 15.5f) }
    }

    val Back: ImageVector = icon("Back") {
        stroke { moveTo(14.5f, 5f); lineTo(7.5f, 12f); lineTo(14.5f, 19f) }
    }

    val Forward: ImageVector = icon("Forward") {
        stroke { moveTo(9.5f, 5f); lineTo(16.5f, 12f); lineTo(9.5f, 19f) }
    }

    val More: ImageVector = icon("More") {
        stroke { moveTo(6f, 12f); lineTo(6.2f, 12f) }
        stroke { moveTo(12f, 12f); lineTo(12.2f, 12f) }
        stroke { moveTo(18f, 12f); lineTo(18.2f, 12f) }
    }

    val Close: ImageVector = icon("Close") {
        stroke { moveTo(5.5f, 5.5f); lineTo(18.5f, 18.5f) }
        stroke { moveTo(18.5f, 5.5f); lineTo(5.5f, 18.5f) }
    }

    val External: ImageVector = icon("External") {
        stroke { moveTo(13f, 4f); lineTo(20f, 4f); lineTo(20f, 11f) }
        stroke { moveTo(20f, 4f); lineTo(11f, 13f) }
        stroke { moveTo(17f, 15f); lineTo(17f, 20f); lineTo(4f, 20f); lineTo(4f, 7f); lineTo(9f, 7f) }
    }

    val Generate: ImageVector = icon("Generate") {
        stroke { moveTo(4f, 6f); lineTo(20f, 6f) }
        stroke { moveTo(4f, 12f); lineTo(14f, 12f) }
        stroke { moveTo(4f, 18f); lineTo(17f, 18f) }
    }

    val Shield: ImageVector = icon("Shield") {
        stroke { moveTo(12f, 3.5f); lineTo(19.5f, 6.5f); lineTo(19.5f, 12f); curveTo(19.5f, 16.5f, 16f, 19.5f, 12f, 20.5f); curveTo(8f, 19.5f, 4.5f, 16.5f, 4.5f, 12f); lineTo(4.5f, 6.5f); close() }
    }

    val Delete: ImageVector = icon("Delete") {
        stroke { moveTo(5.5f, 7f); lineTo(18.5f, 7f) }
        stroke { moveTo(7.5f, 7f); lineTo(8.5f, 20f); lineTo(15.5f, 20f); lineTo(16.5f, 7f) }
        stroke { moveTo(9.5f, 7f); lineTo(9.5f, 4f); lineTo(14.5f, 4f); lineTo(14.5f, 7f) }
    }

    val Edit: ImageVector = icon("Edit") {
        stroke { moveTo(4f, 20f); lineTo(4f, 16f); lineTo(16f, 4f); lineTo(20f, 8f); lineTo(8f, 20f); close() }
    }

    val Check: ImageVector = icon("Check") {
        stroke { moveTo(5f, 12.5f); lineTo(9.5f, 17f); lineTo(19f, 7f) }
    }
}
