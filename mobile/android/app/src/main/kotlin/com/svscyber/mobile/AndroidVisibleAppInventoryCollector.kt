package com.svscyber.mobile

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

/** One-shot inventory of launcher applications visible under the manifest query scope. */
class AndroidVisibleAppInventoryCollector(private val context: Context) {
    data class Result(
        val observedAtEpochMs: Long,
        val scope: String,
        val visibilityMayBeFiltered: Boolean,
        val truncated: Boolean,
        val applications: List<Map<String, Any?>>,
        val events: List<NativeEvent>,
    )

    fun collect(requestedLimit: Int): Result {
        val limit = requestedLimit.coerceIn(1, MAX_APPLICATIONS)
        val packageManager = context.packageManager
        val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val packageNames = packageManager.queryIntentActivities(query, PackageManager.MATCH_DEFAULT_ONLY)
            .mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .sorted()
        val truncated = packageNames.size > limit
        val selected = packageNames.take(limit)
        var inaccessiblePackages = 0
        var permissionsTruncated = false
        val observedAt = System.currentTimeMillis()
        val applications = selected.mapNotNull { packageName ->
            try {
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                val appInfo = packageInfo.applicationInfo ?: run {
                    inaccessiblePackages++
                    return@mapNotNull null
                }
                val requestedPermissions = packageInfo.requestedPermissions.orEmpty()
                    .asSequence()
                    .filter { it.isNotBlank() }
                    .distinct()
                    .sorted()
                    .toList()
                if (requestedPermissions.size > MAX_PERMISSIONS_PER_APP) {
                    permissionsTruncated = true
                }
                val boundedRequested = requestedPermissions.take(MAX_PERMISSIONS_PER_APP)
                val grantedPermissions = boundedRequested.filter { permission ->
                    packageManager.checkPermission(permission, packageName) == PackageManager.PERMISSION_GRANTED
                }
                val installer = installerPackageName(packageManager, packageName)
                mapOf(
                    "packageName" to packageName,
                    "label" to packageLabel(packageManager, appInfo, packageName),
                    "versionName" to packageInfo.versionName?.take(MAX_VERSION_LENGTH),
                    "versionCode" to packageInfo.longVersionCode,
                    "installerPackageName" to installer,
                    "isSystemApp" to isSystemApp(appInfo),
                    "requestedPermissions" to boundedRequested,
                    "grantedPermissions" to grantedPermissions,
                )
            } catch (_: PackageManager.NameNotFoundException) {
                // Apps can disappear between the launcher query and metadata read.
                inaccessiblePackages++
                null
            } catch (_: SecurityException) {
                inaccessiblePackages++
                null
            }
        }

        val scope = SCOPE
        val visibilityMayBeFiltered = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        val appsWithDeclaredPermissions = applications.count {
            (it["requestedPermissions"] as? List<*>)?.isNotEmpty() == true
        }
        val appsWithGrantedPermissions = applications.count {
            (it["grantedPermissions"] as? List<*>)?.isNotEmpty() == true
        }
        val collectionOperation = if (inaccessiblePackages > 0) "degraded" else "completed"
        val events = listOf(
            event("AND-012", observedAt, collectionOperation, mapOf(
                "scope" to scope,
                "inventorySchemaVersion" to INVENTORY_SCHEMA_VERSION,
                "visibilityMayBeFiltered" to visibilityMayBeFiltered,
                "truncated" to truncated,
                "permissionsTruncated" to permissionsTruncated,
                "packageCount" to applications.size,
                "inaccessiblePackageCount" to inaccessiblePackages,
                "applications" to applications,
            )),
            event("AND-013", observedAt, collectionOperation, mapOf(
                "scope" to scope,
                "packageCount" to applications.size,
                "installerSourceAvailableCount" to applications.count { it["installerPackageName"] != null },
            )),
            event("AND-016", observedAt, collectionOperation, mapOf(
                "scope" to scope,
                "packageCount" to applications.size,
                "systemAppCount" to applications.count { it["isSystemApp"] == true },
                "userAppCount" to applications.count { it["isSystemApp"] == false },
            )),
            event("AND-025", observedAt, collectionOperation, mapOf(
                "scope" to scope,
                "packageCount" to applications.size,
                "appsWithDeclaredPermissions" to appsWithDeclaredPermissions,
                "permissionsTruncated" to permissionsTruncated,
                "inaccessiblePackageCount" to inaccessiblePackages,
            )),
            event("AND-026", observedAt, collectionOperation, mapOf(
                "scope" to scope,
                "packageCount" to applications.size,
                "appsWithGrantedPermissions" to appsWithGrantedPermissions,
                "permissionsTruncated" to permissionsTruncated,
                "inaccessiblePackageCount" to inaccessiblePackages,
            )),
        )
        return Result(
            observedAtEpochMs = observedAt,
            scope = scope,
            visibilityMayBeFiltered = visibilityMayBeFiltered,
            truncated = truncated,
            applications = applications,
            events = events,
        )
    }

    private fun event(
        capabilityId: String,
        observedAt: Long,
        operation: String,
        evidence: Map<String, Any?>,
    ) = NativeEvent(
        capabilityId = capabilityId,
        occurredAtEpochMs = observedAt,
        observedAtEpochMs = observedAt,
        availability = "available",
        operation = operation,
        freshness = "fresh",
        evidence = evidence,
    )

    private fun packageLabel(
        packageManager: PackageManager,
        applicationInfo: ApplicationInfo,
        packageName: String,
    ): String {
        val label = packageManager.getApplicationLabel(applicationInfo).toString()
            .replace(Regex("[\\r\\n\\t]+"), " ")
            .trim()
            .take(MAX_LABEL_LENGTH)
        return label.ifEmpty { packageName }
    }

    private fun isSystemApp(info: ApplicationInfo): Boolean =
        info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    @Suppress("DEPRECATION")
    private fun installerPackageName(packageManager: PackageManager, packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            packageManager.getInstallerPackageName(packageName)
        }?.take(MAX_PACKAGE_NAME_LENGTH)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: SecurityException) {
        null
    }

    companion object {
        const val SCOPE = "launchable_packages_visible_to_this_app"
        const val INVENTORY_SCHEMA_VERSION = 1
        const val MAX_APPLICATIONS = 200
        private const val MAX_PERMISSIONS_PER_APP = 128
        private const val MAX_LABEL_LENGTH = 120
        private const val MAX_VERSION_LENGTH = 100
        private const val MAX_PACKAGE_NAME_LENGTH = 255
    }
}
