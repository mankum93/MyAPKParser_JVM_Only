package com.jaredrummler.apkparser

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.io.File

class ApkParserExt {
    companion object {
        @JvmStatic
        fun create(pm: PackageManager, packageName: String): ApkParser {
            val sourceDir = pm.getApplicationInfo(packageName, 0).sourceDir
            return ApkParser.create(File(sourceDir))
        }
        @JvmStatic
        fun create(packageInfo: PackageInfo): ApkParser {
            val sourceDir = packageInfo.applicationInfo.sourceDir
            return ApkParser.create(File(sourceDir))
        }
        @JvmStatic
        fun create(applicationInfo: ApplicationInfo): ApkParser {
            val sourceDir = applicationInfo.sourceDir
            return ApkParser.create(File(sourceDir))
        }
    }
}
