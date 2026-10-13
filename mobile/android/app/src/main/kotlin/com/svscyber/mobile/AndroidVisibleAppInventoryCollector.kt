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
        val permissionsTruncated: Boolean,
        val applications: List<Map<String, Any?>>,
        val events: List<NativeEvent>,
    )

    fun collect(requestedLimit: Int): Result {
        val limit = requestedLimit.coerceIn(1, MAX_APPLICATIONS)
        val packageManager = context.packageManager
        val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        // The intent already specifies CATEGORY_LAUNCHER. MATCH_DEFAULT_ONLY
        // would additionally require CATEGORY_DEFAULT and can hide launcher apps.
        val discoveredPackageNames = packageManager.queryIntentActivities(query, 0)
            .mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .sorted()
        val packageNames = discoveredPackageNames.filter { it.length <= MAX_PACKAGE_NAME_LENGTH }
        val truncated = packageNames.size > limit
        val selected = packageNames.take(limit)
        var inaccessiblePackages = discoveredPackageNames.size - packageNames.size
        var permissionsTruncated = false
        val observedAt = System.currentTimeMillis()
        val applications = selected.mapNotNull { packageName ->
            try {
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                val appInfo = packageInfo.applicationInfo ?: run {
                    inaccessiblePackages++
                    return@mapNotNull null
                }
                val requestedNames = packageInfo.requestedPermissions.orEmpty()
                val permissionFlags = packageInfo.requestedPermissionsFlags
                val permissionGrantStateAvailable = requestedNames.isEmpty() ||
                    permissionFlags?.size == requestedNames.size
                val permissionEntries = requestedNames.mapIndexedNotNull { index, permission ->
                    if (permission.isNullOrBlank()) {
                        null
                    } else if (permission.length > MAX_PERMISSION_NAME_LENGTH) {
                        permissionsTruncated = true
                        null
                    } else {
                        permission to (
                        permissionFlags?.getOrNull(index)?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) ==
                            PackageInfo.REQUESTED_PERMISSION_GRANTED
                        )
                    }
                }.distinctBy { it.first }.sortedBy { it.first }
                if (permissionEntries.size > MAX_PERMISSIONS_PER_APP) {
                    permissionsTruncated = true
                }
                val boundedEntries = permissionEntries.take(MAX_PERMISSIONS_PER_APP)
                val boundedRequested = boundedEntries.map { it.first }
                val grantedPermissions = boundedEntries
                    .filter { permissionGrantStateAvailable && it.second }
                    .map { it.first }
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
                    "permissionGrantStateAvailable" to permissionGrantStateAvailable,
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
            permissionsTruncated = permissionsTruncated,
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
        }?.takeIf { it.length <= MAX_PACKAGE_NAME_LENGTH }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: SecurityException) {
        null
    }

    companion object {
        const val SCOPE = "launchable_packages_visible_to_this_app"
        const val INVENTORY_SCHEMA_VERSION = 1
        const val MAX_APPLICATIONS = 200
        // Keep the largest journal event bounded even when a device has many
        // launcher apps with unusually large permission declarations.
        private const val MAX_PERMISSIONS_PER_APP = 32
        private const val MAX_PERMISSION_NAME_LENGTH = 255
        private const val MAX_LABEL_LENGTH = 120
        private const val MAX_VERSION_LENGTH = 100
        private const val MAX_PACKAGE_NAME_LENGTH = 255
    }
}
