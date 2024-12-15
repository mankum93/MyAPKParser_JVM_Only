/*
 * Copyright (c) 2015, Jared Rummler
 * Copyright (c) 2015, Liu Dong
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.jaredrummler.apkparser

import com.jaredrummler.apkparser.exception.ParserException
import com.jaredrummler.apkparser.model.AndroidManifest
import com.jaredrummler.apkparser.model.ApkMeta
import com.jaredrummler.apkparser.model.CertificateMeta
import com.jaredrummler.apkparser.model.DexClass
import com.jaredrummler.apkparser.model.DexInfo
import com.jaredrummler.apkparser.model.Icon
import com.jaredrummler.apkparser.parser.ApkMetaTranslator
import com.jaredrummler.apkparser.parser.BinaryXmlParser
import com.jaredrummler.apkparser.parser.CertificateParser
import com.jaredrummler.apkparser.parser.CompositeXmlStreamer
import com.jaredrummler.apkparser.parser.DexParser
import com.jaredrummler.apkparser.parser.ResourceTableParser
import com.jaredrummler.apkparser.parser.XmlStreamer
import com.jaredrummler.apkparser.parser.XmlTranslator
import com.jaredrummler.apkparser.struct.AndroidConstants
import com.jaredrummler.apkparser.struct.dex.DexHeader
import com.jaredrummler.apkparser.struct.resource.ResourceTable
import com.jaredrummler.apkparser.utils.Utils
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.text.ParseException
import java.util.Locale
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.security.cert.CertificateException

class ApkParser private constructor(file: File) : Closeable {
    private lateinit var dexInfos: MutableList<DexInfo?> // multi-dex
    private var dex: DexInfo? = null
    private var resourceTable: ResourceTable? = null

    @get:Throws(IOException::class, ParseException::class)
    var androidManifest: AndroidManifest? = null
        /**
         * @return Object holding information about the AndroidManifest and it's declared activities,
         * services, receivers, intent-filters, etc.
         * @throws IOException
         * if parsing the AndroidManifest failed.
         */
        get() {
            if (field == null) {
                // TODO: clean up. We are parsing XML twice.
                field = AndroidManifest(getApkMeta(), manifestXml)
            }
            return field
        }
        private set
    private var manifestXml: String? = null
    private var apkMeta: ApkMeta? = null
    private var locales: Set<Locale>? = null
    private var certificate: CertificateMeta? = null
    private lateinit var zipFile: ZipFile
    private var apkFile: File? = null
    private var preferredLocale = DEFAULT_LOCALE

    init {
        try {
            apkFile = file
            zipFile = ZipFile(file)
        } catch (e: IOException) {
            throw InvalidApkException(String.format("Invalid APK: %s", file.absolutePath), e)
        }
    }

    /**
     * @return decoded AndroidManifest.xml
     */
    @Throws(IOException::class)
    fun getManifestXml(): String? {
        if (manifestXml == null) {
            parseManifestXml()
        }
        return manifestXml
    }

    /**
     * @return decoded AndroidManifest.xml
     */
    @Throws(IOException::class)
    fun getApkMeta(): ApkMeta? {
        if (apkMeta == null) {
            parseApkMeta()
        }
        return apkMeta
    }

    /**
     * get locales supported from resource file
     *
     * @return decoded AndroidManifest.xml
     */
    @Throws(IOException::class)
    fun getLocales(): Set<Locale>? {
        if (locales == null) {
            parseResourceTable()
        }
        return locales
    }

    @get:Throws(IOException::class, CertificateException::class)
    val certificateMeta: CertificateMeta?
        get() {
            if (certificate == null) {
                parseCertificate()
            }
            return certificate
        }

    @Throws(IOException::class, CertificateException::class)
    private fun parseCertificate() {
        var entry: ZipEntry? = null
        val enu = zipFile!!.entries()
        while (enu.hasMoreElements()) {
            val ne = enu.nextElement()
            if (ne.isDirectory) {
                continue
            }
            if (ne.name.uppercase(Locale.getDefault()).endsWith(".RSA") ||
                ne.name.uppercase(Locale.getDefault()).endsWith(".DSA")
            ) {
                entry = ne
                break
            }
        }
        if (entry == null) {
            throw ParserException("ApkParser certificate not found")
        }
        val `in` = zipFile.getInputStream(entry)
        val parser = CertificateParser(`in`)
        certificate = parser.parse()
        `in`.close()
    }

    @Throws(IOException::class)
    private fun parseApkMeta() {
        if (manifestXml == null) {
            parseManifestXml()
        }
    }

    @Throws(IOException::class)
    private fun parseManifestXml() {
        val xmlTranslator = XmlTranslator()
        val translator = ApkMetaTranslator()
        val xmlStreamer: XmlStreamer = CompositeXmlStreamer(xmlTranslator, translator)
        transBinaryXml(AndroidConstants.MANIFEST_FILE, xmlStreamer)
        manifestXml = xmlTranslator.xml
        if (manifestXml == null) {
            throw ParserException("manifest xml not exists")
        }
        apkMeta = translator.apkMeta
    }

    /**
     * trans binary xml file to text xml file.
     *
     * @param path
     * the xml file path in apk file
     * @return the text. null if file not exists
     * @throws IOException
     */
    @Throws(IOException::class)
    fun transBinaryXml(path: String): String? {
        val entry = Utils.getEntry(zipFile, path) ?: return null
        if (resourceTable == null) {
            parseResourceTable()
        }
        try {
            val xmlTranslator = XmlTranslator()
            transBinaryXml(path, xmlTranslator)
            return xmlTranslator.xml
        } catch (e: ParserException) {
            // plain text file
            val `in` = zipFile!!.getInputStream(entry)
            val baos = ByteArrayOutputStream(8192)
            val buffer = ByteArray(8192)
            var length: Int
            while ((`in`.read(buffer).also { length = it }) != -1) {
                baos.write(buffer, 0, length)
            }
            `in`.close()
            return baos.toString("UTF-8")
        }
    }

    @get:Throws(IOException::class)
    val iconFile: Icon?
        /**
         * get the apk icon file as bytes.
         *
         * @return the apk icon data,null if icon not found
         * @throws IOException
         */
        get() {
            val apkMeta = getApkMeta()
            if (apkMeta!!.icon == null) {
                return null
            }
            return Icon(apkMeta.icon, getFileData(apkMeta.icon))
        }

    @Throws(IOException::class)
    private fun transBinaryXml(path: String, xmlStreamer: XmlStreamer) {
        val entry = Utils.getEntry(zipFile, path) ?: return
        if (resourceTable == null) {
            parseResourceTable()
        }
        val `in` = zipFile!!.getInputStream(entry)
        val buffer = ByteBuffer.wrap(Utils.toByteArray(`in`))
        val binaryXmlParser = BinaryXmlParser(buffer, resourceTable)
        binaryXmlParser.locale = preferredLocale
        binaryXmlParser.xmlStreamer = xmlStreamer
        binaryXmlParser.parse()
    }

    /**
     * Return all classes.dex files. If an app is using multi-dex there will be more than one dex
     * file.
     *
     * @return list of information about dex files.
     * @throws IOException
     * if an error occurs while parsing the DEX file(s).
     */
    @Throws(IOException::class)
    fun getDexInfos(): List<DexInfo?>? {
        if (dexInfos == null) {
            parseDexFiles()
        }
        return dexInfos
    }

    @get:Throws(IOException::class)
    val dexInfo: DexInfo?
        /**
         * Get info about classes.dex. Use [.getDexInfos] for apps using multidex.
         *
         * @return info about classes.dex
         * @throws IOException if an error occurs while parsing classes.dex
         */
        get() {
            if (dex == null) {
                dex = parseDexFile()
            }
            return dex
        }

    @get:Throws(IOException::class)
    @get:Deprecated("")
    val dexClasses: Array<DexClass>
        /**
         * Get class info from DEX file. Currently only class name
         */
        get() {
            if (dex == null) {
                dex = parseDexFile()
            }
            return dex!!.classes
        }

    @get:Throws(IOException::class)
    @get:Deprecated("")
    val dexHeader: DexHeader
        get() {
            if (dex == null) {
                dex = parseDexFile()
            }
            return dex!!.header
        }

    @Throws(IOException::class)
    private fun parseDexFiles() {
        dexInfos = ArrayList()
        dexInfos.add(dexInfo)
        for (i in 2..1000 - 1) {
            val path = String.format("classes%d.dex", i)
            val entry = Utils.getEntry(zipFile, path) ?: break
            val `in` = zipFile!!.getInputStream(entry)
            val buffer = ByteBuffer.wrap(Utils.toByteArray(`in`))
            val dexParser = DexParser(buffer)
            dexInfos.add(dexParser.parse())
        }
    }

    @Throws(IOException::class)
    private fun parseDexFile(): DexInfo {
        val entry =
            Utils.getEntry(zipFile, AndroidConstants.DEX_FILE)
                ?: throw ParserException(AndroidConstants.DEX_FILE + " not found")
        val `in` = zipFile!!.getInputStream(entry)
        val buffer = ByteBuffer.wrap(Utils.toByteArray(`in`))
        val dexParser = DexParser(buffer)
        return dexParser.parse()
    }

    /**
     * read file in apk into bytes
     */
    @Throws(IOException::class)
    fun getFileData(path: String?): ByteArray? {
        val entry = Utils.getEntry(zipFile, path) ?: return null
        val inputStream = zipFile!!.getInputStream(entry)
        return Utils.toByteArray(inputStream)
    }

    /**
     * @return One of:
     * [ApkSignStatus.SIGNED],
     * [ApkSignStatus.NOT_SIGNED],
     * [ApkSignStatus.INCORRECT]
     * @throws IOException
     * if reading the APK file failed.
     */
    @Throws(IOException::class)
    fun verifyApk(): Int {
        val entry = Utils.getEntry(zipFile, "META-INF/MANIFEST.MF")
            ?: // apk is not signed;
            return ApkSignStatus.NOT_SIGNED

        val jarFile = JarFile(apkFile)
        val entries = jarFile.entries()
        val buffer = ByteArray(8192)

        while (entries.hasMoreElements()) {
            val e = entries.nextElement()
            if (e.isDirectory) {
                continue
            }
            try {
                // Read in each jar entry. A security exception will be thrown if a signature/digest check fails.
                val `in` = jarFile.getInputStream(e)
                var count: Int
                while ((`in`.read(buffer, 0, buffer.size).also { count = it }) != -1) {
                    // Don't care
                }
                `in`.close()
            } catch (se: SecurityException) {
                return ApkSignStatus.INCORRECT
            }
        }
        return ApkSignStatus.SIGNED
    }

    @Throws(IOException::class)
    private fun parseResourceTable() {
        val entry = Utils.getEntry(zipFile, AndroidConstants.RESOURCE_FILE)
        if (entry == null) {
            // if no resource entry has been found, we assume it is not needed by this APK
            resourceTable = ResourceTable()
            locales = emptySet()
            return
        }
        resourceTable = ResourceTable()
        locales = emptySet()
        val `in` = zipFile!!.getInputStream(entry)
        val buffer = ByteBuffer.wrap(Utils.toByteArray(`in`))
        val resourceTableParser = ResourceTableParser(buffer)
        resourceTableParser.parse()
        resourceTable = resourceTableParser.resourceTable
        locales = resourceTableParser.locales
    }

    override fun close() {
        resourceTable = null
        certificate = null
        try {
            zipFile!!.close()
        } catch (ignored: Exception) {
        }
    }

    fun getPreferredLocale(): Locale {
        return preferredLocale
    }

    /**
     * The locale preferred. Will cause getManifestXml / getApkMeta to return different values.
     * The default value is from os default locale setting.
     */
    fun setPreferredLocale(locale: Locale) {
        if (!Utils.equals(preferredLocale, locale)) {
            preferredLocale = locale
            manifestXml = null
            apkMeta = null
        }
    }

    object ApkSignStatus {
        const val NOT_SIGNED: Int = 0x00
        const val INCORRECT: Int = 0x01
        const val SIGNED: Int = 0x02
    }

    class InvalidApkException(detailMessage: String?, throwable: Throwable?) :
        RuntimeException(detailMessage, throwable)

    companion object {
        private val DEFAULT_LOCALE: Locale = Locale.US

        fun create(path: String): ApkParser {
            return ApkParser(File(path))
        }

        fun create(file: File): ApkParser {
            return ApkParser(file)
        }
    }
}
