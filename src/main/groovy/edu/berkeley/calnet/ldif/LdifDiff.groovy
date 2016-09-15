/*
 * Copyright (c) 2016, Regents of the University of California and
 * contributors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.berkeley.calnet.ldif

import org.springframework.core.io.ByteArrayResource
import org.springframework.core.io.Resource
import org.springframework.ldap.core.LdapAttributes
import org.springframework.ldap.ldif.parser.LdifParser

import javax.naming.directory.Attribute

/**
 * Compare two LDIF files for differences.
 *
 * <p>
 * Usage from source directory: 
 * {@code ./gradlew run -PappArgs="['origFile.ldif', 'newFile.ldif']"}
 * </p>
 *
 * @author Brian Koehmstedt
 */
class LdifDiff {
    /**
     * Extracts UIDs from DNs that start with "uid=".
     */
    static final UidExtractor uidExtractor = new UidExtractor()

    /**
     * Main entry to compare two LDIF files.
     *
     * @param args args[0] is the original LDIF filename and args[1] is the new LDIF filename.
     */
    static void main(String[] args) {
        if (args.length < 2) {
            printUsage()
            System.exit(1)
        }
        diffLdif(args[0], args[1])
    }

    /**
     * Print usage information to stdout.
     */
    static void printUsage() {
        println("Usage from source directory: ./gradlew run -PappArgs=\"['origFile.ldif', 'newFile.ldif']\"")
    }

    /**
     * Compare two LDIF files for differences.  Prints the results to
     * stdout.
     *
     * @param origFilename File name of the original LDIF file.
     * @param newFilename File name of the new LDIF file.
     */
    static void diffLdif(String origFilename, String newFilename) {
        File origFile = new File(origFilename)
        if (!origFile.exists()) {
            throw new RuntimeException("$origFile not found")
        }
        File newFile = new File(newFilename)
        if (!newFile.exists()) {
            throw new RuntimeException("$newFile not found")
        }

        FileInputStream origFileInputStream = new FileInputStream(origFile)
        FileInputStream newFileInputStream = new FileInputStream(newFile)
        try {
            LinkedHashMap<String, long[]> origIndex = indexLdif(origFileInputStream)
            LinkedHashMap<String, long[]> newIndex = indexLdif(newFileInputStream)
            compareEntries(origFileInputStream, origIndex, newFileInputStream, newIndex)
        }
        finally {
            origFileInputStream.close()
            newFileInputStream.close()
        }
    }

    /**
     * Calculate the index for an LDIF file.
     *
     * @param inputStream The FileInputStream of the LDIF File.
     * @return A LinkedHashMap that represents the index.  The key to the map is the entry DN and the value is a two-element long[] array.  Element 0 is the starting byte position for the entry.  Element 1 is the byte length of the entry.
     */
    static LinkedHashMap<String, long[]> indexLdif(FileInputStream inputStream) {
        final int lineSeparatorLength = System.lineSeparator().bytes.length
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))
        LinkedHashMap<String, long[]> indexMap = [:] as LinkedHashMap<String, long[]>
        long currentPosition = 0
        String line
        long[] currentEntryIndexArray = null
        while ((line = reader.readLine()) != null) {
            if (line.startsWith("dn: ")) {
                currentEntryIndexArray = [currentPosition, -1]
                indexMap.put(line.substring(4), currentEntryIndexArray)
            } else if (line.length() == 0) {
                currentEntryIndexArray[1] = currentPosition - currentEntryIndexArray[0]
            }
            currentPosition += line.bytes.length + lineSeparatorLength
        }
        // reset back to beginning of file
        inputStream.channel.position(0)

        return indexMap
    }

    /**
     * Compare LDIF entries from an original LDIF file and a new LDIF file
     * using a pre-calculated index.  The index contains pointers to each
     * LDIF entry and contains the size of the LDIF entry.
     *
     * @param origInputStream The FileInputStream for the original LDIF file.
     * @param origIndex The index, calculated by indexLdif(), for the original LDIF file.
     * @param newInputStream The FileInputStream for the new LDIF file.
     * @param newIndex The index, calculated by indexLidf(), for the new LDIF file.
     */
    static void compareEntries(FileInputStream origInputStream,
                               LinkedHashMap<String, long[]> origIndex,
                               FileInputStream newInputStream,
                               LinkedHashMap<String, long[]> newIndex) {
        Collection<String> allDns = (((origIndex?.keySet() ?: []) + (newIndex?.keySet() ?: [])) as HashSet<String>).sort()
        int count = 0
        allDns.each { String dn ->
            long[] origIndexEntry = origIndex[dn]
            long[] newIndexEntry = newIndex[dn]

            if (origIndexEntry == null && newIndexEntry == null) {
                throw new RuntimeException("Can't find $dn in either index")
            }

            String origDn = null
            String newDn = null

            // Check for DN changes.  We extract a unique identifier from
            // the DN and see if we can find it in the index by its unique
            // identifier rather than the exact DN match.
            if (origIndexEntry == null) {
                IndexEntrySearchResult searchResult = findIndexEntryByDnUniqueIdentifier(origIndex, dn)
                if (searchResult) {
                    origDn = searchResult.dn
                    origIndexEntry = searchResult.entry
                }
            } else {
                origDn = dn
            }
            if (newIndexEntry == null) {
                IndexEntrySearchResult searchResult = findIndexEntryByDnUniqueIdentifier(newIndex, dn)
                if (searchResult) {
                    newDn = searchResult.dn
                    newIndexEntry = searchResult.entry
                }
            } else {
                newDn = dn
            }

            Long origPosition = (origIndexEntry ? origIndexEntry[0] : null)
            Long newPosition = (newIndexEntry ? newIndexEntry[0] : null)

            // seek to position of entry and read the entry
            LdapAttributes origEntry = null
            LdapAttributes newEntry = null
            if (origIndexEntry != null) {
                origInputStream.channel.position(origPosition)
                ByteArrayResource resource = entryAsByteArrayResource(origInputStream, origIndexEntry[1] as int)
                origEntry = readEntry(resource, origDn)
                if (origEntry == null) {
                    throw new RuntimeException("readEntry() returned null for original $dn despite it being indexed")
                }
            }
            if (newIndexEntry != null) {
                newInputStream.channel.position(newPosition)
                ByteArrayResource resource = entryAsByteArrayResource(newInputStream, newIndexEntry[1] as int)
                newEntry = readEntry(resource, newDn)
                if (newEntry == null) {
                    throw new RuntimeException("readEntry() returned null for new $dn despite it being indexed")
                }
            }

            diffEntry(origEntry, newEntry)

            count++

            if (count % 1000 == 0) {
                println("Processed $count entries")
            }
        }
    }

    /**
     * Result for findIndexEntryByDnUniqueIdentifier()
     */
    static class IndexEntrySearchResult {
        String dn
        long[] entry
    }

    /**
     * For cases where a DN may have changed, find an index entry by
     * extracting the unique identifier from the DN and search the index for
     * that unique identifier to see if there is another DN that matches
     * against the unique identifier.
     *
     * <p>In cases where there may exist multiple DNs for one primary
     * identifier, this search will return the <b>first one</b> it finds in
     * the index keySet.</p>
     *
     * @param index The index to search.
     * @param dn The DN to extract the unique identifier from.
     * @return An instance IndexEntrySearchResult containing the dn and index entry if a match was found.  If not, null is returned.
     */
    static IndexEntrySearchResult findIndexEntryByDnUniqueIdentifier(LinkedHashMap<String, long[]> index, String dn) {
        String uniqueIdentifierDnPrefix = uniqueIdentifierExtractor.extractUniqueIdentifierAsDnPrefix(dn)
        if (uniqueIdentifierDnPrefix) {
            for (Map.Entry<String, long[]> entry : index) {
                if (entry.key.startsWith(uniqueIdentifierDnPrefix)) {
                    return new IndexEntrySearchResult(dn: entry.key, entry: entry.value)
                }
            }
        }
        return null
    }

    /**
     * Overridable method to get a unique identifier extractor for a DN.
     *
     * @return An implementation of the UniqueIdentifierExtractor interface.
     */
    static UniqueIdentifierExtractor getUniqueIdentifierExtractor() {
        return uidExtractor
    }

    /**
     * Read bytes from an InputStream that represent a single LDIF entry.
     *
     * @param inputStream The InputStream to read from.
     * @param length The number of bytes representing the single entry to read.
     * @return The Spring ByteArrayResource containing the bytes of the LDIF entry.
     */
    static ByteArrayResource entryAsByteArrayResource(InputStream inputStream, int length) {
        if (length < 0) {
            throw new IllegalArgumentException("length can't be negative")
        }
        byte[] result = new byte[length]
        int bytesRead = inputStream.read(result, 0, length)
        if (bytesRead != length) {
            throw new RuntimeException("Unable to read $length bytes")
        }
        return new ByteArrayResource(result)
    }

    /**
     * Read an LDIF entry from a Spring Resource that contains the text of a
     * single LDIF entry.
     *
     * @param resource Spring Resource containing the text of a single LDIF entry.
     * @param dn The expected DN of the entry.
     * @return The parsed LdapAttributes of the LDIF entry.
     */
    static LdapAttributes readEntry(Resource resource, String dn) {
        LdifParser parser = new LdifParser(resource)
        parser.open()
        try {
            LdapAttributes entry = parser.record
            if (entry?.name?.toString() != dn) {
                throw new RuntimeException("Entry doesn't match dn $dn.  Instead, it's ${entry?.name?.toString()}.")
            }
            return entry
        }
        finally {
            parser.close()
        }
    }

    /**
     * Compare two LDIF entries and print the differences.
     *
     * @param origEntry The original LdapAttributes LDIF entry.  May be null but origEntry and newEntry cannot both be null.
     * @param newEntry The new LdapAttributes LDIF entry.  May be null but origEntry and newEntry cannot both be null.
     */
    static void diffEntry(LdapAttributes origEntry, LdapAttributes newEntry) {
        if (origEntry == null && newEntry == null) {
            throw new IllegalArgumentException("origEntry and newEntry can't both be null")
        }
        String origDn = origEntry?.name
        String newDn = newEntry?.name
        if (origEntry?.hashCode() != newEntry?.hashCode()) {
            if (origDn == newDn) {
                // DN hasn't changed
                println("\ndn: $origDn")
            } else if (origDn && newDn && origDn != newDn) {
                // DN has been changed
                println("\n- $origDn")
                println("+ $newDn")
            } else if (origDn && !newDn) {
                // DN has been removed
                println("\n- $origDn")
            } else if (!origDn && newDn) {
                // DN has been added
                println("\n+ $newDn")
            } else {
                throw new IllegalStateException("bad DN state")
            }
            Collection<String> attrNames = (((origEntry?.all?.collect { it.ID } ?: []) + (newEntry?.all?.collect { it.ID } ?: [])) as HashSet<String>).sort()

            attrNames.each { String attrName ->
                Attribute origAttr = origEntry?.get(attrName)
                Attribute newAttr = newEntry?.get(attrName)
                if (origAttr?.hashCode() != newAttr?.hashCode()) {
                    Collection<String> origAttrValues = (origAttr?.all?.collect { it.toString() } ?: [])
                    Collection<String> newAttrValues = (newAttr?.all?.collect { it.toString() } ?: [])
                    Collection<String> attrValues = ((origAttrValues + newAttrValues) as HashSet<String>).sort()
                    attrValues.each { String attrValue ->
                        boolean origContains = origAttrValues.contains(attrValue)
                        boolean newContains = newAttrValues.contains(attrValue)
                        if (origContains && !newContains) {
                            // has been removed in new ldif file
                            println("- $attrName: $attrValue")
                        } else if (!origContains && newContains) {
                            // has been added in new ldif file
                            println("+ $attrName: $attrValue")
                        }
                    }
                }
            }
        }
    }
}
