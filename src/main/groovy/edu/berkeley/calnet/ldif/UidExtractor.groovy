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

/**
 * Extract a uid from DNs that start with "uid=".
 *
 * @author Brian Koehmstedt
 */
class UidExtractor implements UniqueIdentifierExtractor {
    /**
     * Extract uid from DN.
     */
    String extractUniqueIdentifier(String dn) {
        if (dn.startsWith("uid=")) {
            return dn.substring(4, dn.indexOf(","))
        } else {
            return null
        }
    }

    /**
     * Creates "uid=uniqueIdentifier" as the prefix to a DN.
     */
    String uniqueIdentifierToDnPrefix(String uniqueIdentifier) {
        if (uniqueIdentifier) {
            return "uid=${uniqueIdentifier},"
        } else {
            return null
        }
    }

    /**
     * Returns "uid=uniqueIdentifier" from a DN that starts with a uid= prefix.
     */
    String extractUniqueIdentifierAsDnPrefix(String dn) {
        return uniqueIdentifierToDnPrefix(extractUniqueIdentifier(dn))
    }
}