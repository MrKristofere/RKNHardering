package com.notcvnt.rknhardering

import android.content.Context
import com.notcvnt.rknhardering.model.LocalProxyOwner

internal object LocalProxyOwnerFormatter {

    fun format(context: Context, owner: LocalProxyOwner): String {
        val singlePackage = owner.packageNames.singleOrNull()
        if (singlePackage != null) {
            val label = owner.appLabels.firstOrNull()?.takeUnless { it == singlePackage }
            return if (label != null) {
                context.getString(R.string.checker_proxy_owner_single, label, singlePackage, owner.uid)
            } else {
                context.getString(R.string.checker_proxy_owner_named_uid, singlePackage, owner.uid)
            }
        }

        if (owner.packageNames.isNotEmpty()) {
            return context.getString(
                R.string.checker_proxy_owner_shared,
                owner.uid,
                owner.packageNames.joinToString(", "),
            )
        }

        val label = owner.appLabels.firstOrNull()
        return if (label != null) {
            context.getString(R.string.checker_proxy_owner_named_uid, label, owner.uid)
        } else {
            context.getString(R.string.checker_proxy_owner_uid_only, owner.uid)
        }
    }

    fun packageName(owner: LocalProxyOwner?): String? = owner?.packageNames?.singleOrNull()
}
