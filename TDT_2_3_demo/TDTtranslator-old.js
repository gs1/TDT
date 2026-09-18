/**
 * ============================================================================
 * GS1 Tag Data Translation (TDT) Engine
 * Version 2.6 (Enterprise Architecture Production Release)
 * ============================================================================
 */

/**
 * Recursively locks down objects and arrays to prevent unauthorized runtime mutation.
 * @param {Object|Array} object - Target data reference context.
 * @returns {Object|Array} Immutable frozen data reference.
 */
function deepFreeze(object) {
    if (object && typeof object === "object") {
        const propNames = Object.getOwnPropertyNames(object);
        for (const name of propNames) {
            const value = object[name];
            if (value && typeof value === "object") {
                deepFreeze(value);
            }
        }
        return Object.freeze(object);
    }
    return object;
}

// ----------------------------------------------------------------------------
// DIAGNOSTIC LAYER: RICH EXTRACTOR EXCEPTION ARCHITECTURE
// ----------------------------------------------------------------------------

class TDTExtractionError extends Error {
    /**
     * Constructs an enriched error instance providing a transparent window into 
     * structural validation faults for engineers unfamiliar with GS1 syntax boundaries.
     * @param {string} message - Human-readable diagnostic description.
     * @param {Object} context - Snapshot parameters of the runtime compilation path.
     */
    constructor(message, context = {}) {
        super(message);
        this.name = "TDTExtractionError";
        this.scheme = context.scheme || null;
        this.failedLevel = context.level || null;
        this.inputBufferSnapshot = context.buffer || null;
        this.gcpLengthEvaluated = context.gcpLength || null;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, TDTExtractionError);
        }
    }
}

// ----------------------------------------------------------------------------
// APPLICATION ENGINE LAYER: BI-DIRECTIONAL TRANSLATION ENGINE
// ----------------------------------------------------------------------------

class TDTtranslator {

    // V8 Engine Optimization: Private Static Regex Map Cache
    static regexBinaryString = /^[01]+$/;
    static regexURNcode40 = /^[A-Z0-9\.:-]+$/;
    static regexFileSafeURISafeBase64 = /^[A-Za-z0-9_-]+$/;
    static regexUpperCaseHexadecimal = /^[0-9A-F]+$/;
    static regexLowerCaseHexadecimal = /^[0-9a-f]+$/;
    static regexHexadecimal = /^[0-9A-Fa-f]+$/;
    static regexAlphanumeric = /^[\x21-\x23\x25-\x5A\x5A-\x7A]+$/;
    static regexAllNumeric = /^[0-9]+$/;
    static regexEightBit = /^[\x00-\x7F]*$/;
    static regexSevenBit = /^[\x20-\x7F]*$/;
    static regexSixBit = /^[\x20-\x5F]*$/;
    static regexFiveBit = /^[\x40-\x5F]*$/;
    static regexDateYYMMDD = /^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)$/;
    static regexDateYYMMDDhhmm = /^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)(?:(?:[01][0-9]|2[0-3])(?:[0-5][0-9])|2400)$/;
    static regexDateYYMMDDorYYMMDDYYMMDD = /^(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)){1,2}$/;
    static regexVariablePrecisionDateTimeYYMMDDhh_mmss = /^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)(?:[01][0-9]|2[0-4])?(?:[0-5][0-9])?(?:[0-5][0-9])?$/;
    static regexCountryCode = /^[A-Z]{2}$/;
    static regexAIkey = /^[0-9]{2,4}$/;
    static regexAIkeyPrioritisedDate = /^(?:11|13|15|16|17|7006|7007)$/;
    static regexOptionalMinus = /^[-]?$/;
    static regexSingleBit = /^[01]$/;
    static regexRule = /^([A-Z0-9_]+)\((.+)\)$/; 
    static regexStatic = /^'(.+)'$/;
    static regexURIEscapeChar = /^[#/%&+,!()*':;<=>?']$/;
    static regexURNEscapeChar = /^["#%&()/<>?]$/;
    static regexPermittedHostname = /^[!%-?A-Z_a-z\x22]+$/;
    static tdtDataContainer = 'tdt:epcTagDataTranslation';

    // Static Character Alphabets Map
    static alphabetURNcode40 = " ABCDEFGHIJKLMNOPQRSTUVWXYZ-.:0123456789";
    static alphabetFileSafeURISafeBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static alphabetUpperCaseHexadecimal = "0123456789ABCDEF";
    static alphabetLowerCaseHexadecimal = "0123456789abcdef";
    static fromAItoPrioritisedDateIndicator = {"11":"0000","13":"0001","15":"0010","16":"0011","17":"0100","7006":"0101","7007":"0110"};

    // Encapsulated Substring Allocation Mapping Optimization Cache Tables
    static optimisation7bitTableA = [];
    static optimisation14bitTableB1 = [];
    static optimisation14bitTableB2 = [];
    static optimisation14bitTableB3 = [];
    static optimisation14bitTableB4 = [];

    /**
     * Drop-in Backwards Compatible Object Constructor Loop.
     */
    constructor() {
        this.tdtData = {};
        this.gcpLengths = {};

        // Explicit Instance Self-Binding Policy
        this.translate = this.translate.bind(this);
        this.autodetect = this.autodetect.bind(this);

        this.initialized = this.#fetchAllData(); 
    }

    #fetchAllData() {
        const promises = [
            this.#fetchZipData('./TDT_JSON_artefacts.zip'),
            this.#fetchPrefixLengthData('./gcpprefixformatlist.json')
        ];

        return Promise.all(promises)
            .then(([loadedData]) => {
                let manifestData = TDTtranslator.#unwrapDataByFilename(loadedData, "manifest.json");

                this.tdtData.table = {};
                this.tdtData.scheme = {};

                for (let tableEntry of manifestData.tables) {
                    console.debug(JSON.stringify(tableEntry));
                    let rawData = TDTtranslator.#unwrapDataByFilename(loadedData, tableEntry.file);
                    
                    if (tableEntry.table === "Opt_A") {
                        TDTtranslator.optimisation7bitTableA = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B1") {
                        TDTtranslator.optimisation14bitTableB1 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B2") {
                        TDTtranslator.optimisation14bitTableB2 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B3") {
                        TDTtranslator.optimisation14bitTableB3 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B4") {
                        TDTtranslator.optimisation14bitTableB4 = TDTtranslator.normalizeGS1Table(rawData);
                    } else {
                        let rows = {};
                        for (let row of rawData.rows) {
                            rows[row.a] = row;
                        }
                        this.tdtData.table[tableEntry.table] = Object.freeze(rows);
                    }
                }

                // Protect optimization cache surfaces from internal state leaks
                deepFreeze(TDTtranslator.optimisation7bitTableA);
                deepFreeze(TDTtranslator.optimisation14bitTableB1);
                deepFreeze(TDTtranslator.optimisation14bitTableB2);
                deepFreeze(TDTtranslator.optimisation14bitTableB3);
                deepFreeze(TDTtranslator.optimisation14bitTableB4);

                for (let scheme of manifestData.definitionFiles) {
                    console.debug(JSON.stringify(scheme));
                    this.tdtData.scheme[scheme.scheme] = deepFreeze(TDTtranslator.#unwrapDataByFilename(loadedData, scheme.file));
                }
            })
            .catch(error => {
                console.error('Error fetching structural verification sources:', error);
                throw error;
            });
    }
    
    #fetchZipData(url) {
        return fetch(url)
            .then(response => {
                if (!response.ok) throw new Error(`Failed to fetch zip package data from ${url}`);
                return response.blob();
            })
            .then(blob => JSZip.loadAsync(blob))
            .then(function (zip) {
                const promises = [];
                zip.forEach((relativePath, zipEntry) => {
                    if (!(relativePath.startsWith('__MACOS')) && (relativePath.endsWith('.json'))) {
                        let localPart = relativePath.replace(/^.+?\//, "");
                        let relativePathWithoutSuffix = localPart.replace(/\.json$/, "");
                        console.debug('Parsing ' + relativePath);
                        promises.push(
                            zipEntry.async('text').then(
                                function parseJson(jsonString) {
                                    return { "id": relativePathWithoutSuffix, "file": localPart, "data": JSON.parse(jsonString) };
                                }
                            )
                        );
                    }
                });
                return Promise.all(promises);
            })
            .catch(error => {
                console.error(`Error loading file assets zip from ${url}:`, error);
                throw error;
            });
    }

    #fetchPrefixLengthData(url) {
        return fetch(url)
            .then(response => {
                if (!response.ok) throw new Error(`Failed to fetch prefix length JSON mapping from ${url}`);
                return response.json();
            })
            .then(data => {
                for (let index in data.GCPPrefixFormatList.entry) {
                    let entry = data.GCPPrefixFormatList.entry[index];
                    this.gcpLengths[entry.prefix] = entry.gcpLength;
                }
                console.debug("GCP Length lookup arrays loaded completely.");
            });
    }

    #lookupPrefixLength(string) {
        let prefix = string.substr(0, 11);
        while (prefix.length > 0) {
            if (prefix in this.gcpLengths) return this.gcpLengths[prefix];
            prefix = prefix.slice(0, -1);
        }
        return -1;
    }

    processData() {
        if (this.tdtData) {
            console.info("TDT data loaded");
            console.info("supported schemes = " + JSON.stringify(Object.keys(this.tdtData.scheme), null, 2));
            console.info("data tables loaded = " + JSON.stringify(Object.keys(this.tdtData.table), null, 2));
        } else {
            console.error('Data not available yet. Please wait for initialization.');
        }
    }

    // ------------------------------------------------------------------------
    // SCHEMATIC PARSING UTILITIES & SHAPE NORMALIZERS
    // ------------------------------------------------------------------------
    
    static normalizeGS1Table(rawJSON) {
        if (!rawJSON || !rawJSON.rows) return [];
        const columns = rawJSON.columns || [];
        const binaryKey = columns.find(c => c.name === "binary" || c.title === "binary")?.id || "a";
        const substringKey = columns.find(c => c.name === "substring" || c.title === "substring")?.id || "b";

        return rawJSON.rows.map(row => ({
            "binary": String(row[binaryKey]).trim(),
            "substring": String(row[substringKey]).trim()
        }));
    }

    static reverseHash(obj) {
        let reversed = {};
        let keys = Object.keys(obj);
        for (let i = 0; i < keys.length; i++) {
            reversed[obj[keys[i]]] = keys[i];
        }
        return reversed;
    }

    static get fromPrioritisedDateIndicatorToAI() {
        return TDTtranslator.reverseHash(TDTtranslator.fromAItoPrioritisedDateIndicator);
    }

    static calculateGS1CheckDigit(gs1IDValue) {
        if (TDTtranslator.regexAllNumeric.test(gs1IDValue)) {
            let counter = 0;
            let total = 0;
            for (let i = gs1IDValue.length - 1; i >= 0; i--) {
                total += ((gs1IDValue.charAt(i)) * (3 - 2 * (counter % 2)));
                counter++;
            }
            return (10 - (total % 10)) % 10;
        } else {
            throw new Error("Cannot calculate a GS1 Check Digit for " + gs1IDValue + " because it is not a numeric string of digits 0-9 only");
        }
    }

    static matchEncodingIndicator(indicator) {
        return function(element) {
            return element.indicator == indicator;
        }
    }

    // ------------------------------------------------------------------------
    // HIGH-DENSITY PACKING IMPLEMENTATIONS (SECTION 14.5.16 HOSTNAME PROCESSING)
    // ------------------------------------------------------------------------
    
    static internalHostname2Binary(hostname) {
        if (!hostname) throw new Error("Empty Hostname provided");
        if (!TDTtranslator.regexPermittedHostname.test(hostname)) {
            throw new Error("Validation Error: Hostname contains characters forbidden by standard GS1 TDT schemas.");
        }

        const localPrePad = (str, padChar, len) => str.length < len ? padChar.repeat(len - str.length) + str : str;
        const buildLengthIndicator = (l) => localPrePad(l.toString(2), "0", 6);

        // Strategy A: URN Code 40 Polynomial Packing Method
        let urnResult = null;
        if (TDTtranslator.regexURNcode40.test(hostname)) {
            let workStr = hostname;
            if (workStr.length % 3 > 0) {
                workStr += " ".repeat(3 - (workStr.length % 3));
            }
            let binaryPayload = "";
            for (let t = 0; t < workStr.length / 3; t++) {
                const i1 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t));
                const i2 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 1));
                const i3 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 2));
                const b = localPrePad(((1600 * i1 + 40 * i2 + i3 + 1) >>> 0).toString(2), "0", 16);
                binaryPayload += b;
            }
            urnResult = {
                indicator: "0",
                lengthBin: buildLengthIndicator(hostname.length),
                payload: binaryPayload,
                totalBits: 1 + 6 + binaryPayload.length
            };
        }

        // Strategy B: Optimized Huffman-Substring 7-bit ASCII Tokenized Matcher
        let asciiResult = null;
        try {
            let optimisations = [];
            let tables = [
                TDTtranslator.optimisation14bitTableB4, 
                TDTtranslator.optimisation14bitTableB3, 
                TDTtranslator.optimisation7bitTableA, 
                TDTtranslator.optimisation14bitTableB1, 
                TDTtranslator.optimisation14bitTableB2
            ];
            
            for (let table of tables) {
                for (let el of table) {
                    if (hostname.indexOf(el.substring) > -1) optimisations.push(el);
                }
            }
            let finalOptimisations = [];
            let optimisationsRemoved = hostname;
            for (let el of optimisations) {
                let p = optimisationsRemoved.indexOf(el.substring);
                if (p > -1) {
                    finalOptimisations.push(el);
                    optimisationsRemoved = optimisationsRemoved.replace(el.substring, "");
                }
            }
            let tokens = [];
            let cursor = 0;
            let sb = [];
            while (cursor < hostname.length) {
                let foundOptimisation = false;
                for (let o of finalOptimisations) {
                    if (hostname.indexOf(o.substring) === cursor) {
                        if (sb.length > 0) { tokens.push(sb.join("")); sb = []; }
                        tokens.push(o);
                        cursor += o.substring.length;
                        foundOptimisation = true;
                        break;
                    }
                }
                if (!foundOptimisation) { sb.push(hostname.charAt(cursor)); cursor++; }
            }
            if (sb.length > 0) tokens.push(sb.join(""));

            let finalBinaryBuffer = [];
            for (let t of tokens) {
                if (typeof t === "string") {
                    for (let i = 0; i < t.length; i++) {
                        const charCode = t.charCodeAt(i);
                        if (charCode > 127) throw new Error("Non-ASCII character");
                        finalBinaryBuffer.push(charCode.toString(2).padStart(8, "0").substr(1));
                    }
                } else {
                    finalBinaryBuffer.push(t.binary);
                }
            }
            let asciiPayload = finalBinaryBuffer.join("");
            let virtualLength = asciiPayload.length / 7;
            asciiResult = {
                indicator: "1",
                lengthBin: buildLengthIndicator(virtualLength),
                payload: asciiPayload,
                totalBits: 1 + 6 + asciiPayload.length
            };
        } catch (err) {}

        if (urnResult && asciiResult) {
            return (urnResult.totalBits <= asciiResult.totalBits) 
                ? urnResult.indicator + urnResult.lengthBin + urnResult.payload 
                : asciiResult.indicator + asciiResult.lengthBin + asciiResult.payload;
        } else if (urnResult) {
            return urnResult.indicator + urnResult.lengthBin + urnResult.payload;
        } else if (asciiResult) {
            return asciiResult.indicator + asciiResult.lengthBin + asciiResult.payload;
        }
        throw new Error("Character footprint generation error across validation fields.");
    }

    static internalBinary2Hostname(fullBitString) {
        if (!fullBitString || !TDTtranslator.regexBinaryString.test(fullBitString)) {
            throw new Error("Invalid Payload: Must consist solely of 0 and 1 bits.");
        }
        if (fullBitString.length < 7) {
            throw new Error("Framing Error: Structural layout constraints too short to unpack.");
        }

        const encIndicator = fullBitString.charAt(0);
        const lengthIndicatorVal = parseInt(fullBitString.substr(1, 6), 2);
        let payloadBits = fullBitString.substring(7);

        if (encIndicator === "0") {
            // ROUND-TRIP PATCH: Handle non-significant trailing zeros that leaked into the isolated URN 40 block
            if (payloadBits.length % 16 !== 0) {
                let truncatedBits = payloadBits.substring(0, payloadBits.length - (payloadBits.length % 16));
                let droppedBits = payloadBits.substring(truncatedBits.length);
                if (/^0*$/.test(droppedBits)) {
                    payloadBits = truncatedBits;
                } else {
                    throw new Error("Sizing Constraint Fault: URN Code 40 payloads must resolve to multiples of 16 bits.");
                }
            }
            let outputCharacterString = "";
            for (let t = 0; t < (payloadBits.length / 16); t++) {
                const substr = payloadBits.substr(16 * t, 16);
                const n = parseInt(substr, 2);
                const c3 = (n - 1) % 40;
                const c2 = (((n - 1) - c3) / 40) % 40;
                const c1 = (n - 1 - c3 - 40 * c2) / 1600;
                outputCharacterString += TDTtranslator.alphabetURNcode40.charAt(c1) + TDTtranslator.alphabetURNcode40.charAt(c2) + TDTtranslator.alphabetURNcode40.charAt(c3);
            }
            return outputCharacterString.substring(0, lengthIndicatorVal);
        }

        if (encIndicator === "1") {
            let outputCharacterString = "";
            let i = 0;
            while (i < payloadBits.length) {
                let optimizedMatch = false;
                let check14 = payloadBits.substr(i, 14);
                let check7 = payloadBits.substr(i, 7);
                
                let tables = [
                    TDTtranslator.optimisation14bitTableB4, 
                    TDTtranslator.optimisation14bitTableB3, 
                    TDTtranslator.optimisation14bitTableB1, 
                    TDTtranslator.optimisation14bitTableB2, 
                    TDTtranslator.optimisation7bitTableA
                ];
                
                for (let table of tables) {
                    for (let el of table) {
                        if (el.binary.length === 14 && check14 === el.binary) {
                            outputCharacterString += el.substring; i += 14; optimizedMatch = true; break;
                        } else if (el.binary.length === 7 && check7 === el.binary) {
                            outputCharacterString += el.substring; i += 7; optimizedMatch = true; break;
                        }
                    }
                    if (optimizedMatch) break;
                }
                if (!optimizedMatch) {
                    if (i + 7 > payloadBits.length) break; 
                    let chunk = payloadBits.substr(i, 7);
                    let charCode = parseInt(chunk, 2);
                    if (charCode < 32) break; 
                    outputCharacterString += String.fromCharCode(charCode);
                    i += 7;
                }
            }
            return outputCharacterString;
        }
        throw new Error("Unknown strategy identification bit profile encountered.");
    }

    // ------------------------------------------------------------------------
    // SCHEMATIC DECLARATIVE PROCESSING LAYER (MACRO EVALUATORS)
    // ------------------------------------------------------------------------
    
    static processRule(rule, internalMap, options, checkList) {
        console.debug("Processing rule " + JSON.stringify(rule, null, 2));

        if (internalMap.hasOwnProperty(rule.newFieldName)) return;

        let func = TDTtranslator.regexRule.exec(rule.function);
        func.shift();
        if (func.length < 2) {
            throw new Error("Failed parsing rule");
        }
        let args = func[1].split(",");

        let argVals = [];
        for (let a of args) {
            if (TDTtranslator.regexAllNumeric.test(a)) {
                argVals.push(a);
                continue;
            }

            if (a.match(TDTtranslator.regexStatic)) {
                console.debug(a + " is a static value");
                let vals = TDTtranslator.regexStatic.exec(a);
                argVals.push(vals[1]);
                continue;
            }

            console.debug("Looking for " + a);
            if (!internalMap.hasOwnProperty(a)) {
                if (rule.type == "EXTRACT" && !checkList.includes(a) && !options.hasOwnProperty(a)) {
                    console.debug(a + " not in input - skipping rule");
                    return;
                }
                if (rule.type == "FORMAT" && !checkList.includes(rule.newFieldName)) {
                    console.debug(rule.newFieldName + " not required - skipping rule");
                    return;
                }				
                
                if (a === "hostname" && !options.hasOwnProperty("hostname") && options.hasOwnProperty("uriStem") && options.uriStem) {
                    try {
                        let cleanStem = options.uriStem.replace(/^https?:\/\//i, '').split('/')[0];
                        if (cleanStem) {
                            options["hostname"] = cleanStem;
                            console.debug("processRule: Injected fallback hostname derived from URI Stem Base: " + cleanStem);
                        }
                    } catch (stemError) {
                        console.error("processRule: Failed parsing fallback hostname from uriStem:", stemError);
                    }
                }
    
                if (!options.hasOwnProperty(a)) {
                    throw new Error("Missing argument " + a);
                }
                argVals.push(options[a]);
            } else {
                argVals.push(internalMap[a]);
            }
        }
        console.debug("Rule arguments: " + JSON.stringify(argVals));

        switch (func[0]) {
            case "HOSTNAME2BINARY": {
                let targetHostname = argVals[0];

                if (!targetHostname && options.hasOwnProperty("uriStem") && options.uriStem) {
                    try {
                        let cleanStem = options.uriStem.replace(/^https?:\/\//i, '').split('/')[0];
                        if (cleanStem) {
                            targetHostname = cleanStem;
                            console.debug("HOSTNAME2BINARY fallback triggered using domain from URI Stem Base: " + targetHostname);
                        }
                    } catch (stemError) {
                        console.error("Failed to parse fallback hostname from uriStem option:", stemError);
                    }
                }

                if (!targetHostname) {
                    throw new Error("Missing argument hostname: No hostname extracted from input and no valid fallback found in uriStem option.");
                }

                internalMap[rule.newFieldName] = TDTtranslator.internalHostname2Binary(targetHostname);
                break;
            }
            case "BINARY2HOSTNAME": {
                if (argVals[0] && TDTtranslator.regexBinaryString.test(argVals[0])) {
                    try {
                        let decodedHost = TDTtranslator.internalBinary2Hostname(argVals[0]);
                        if (decodedHost && decodedHost.trim().length > 0) {
                            internalMap[rule.newFieldName] = decodedHost.trim();
                            console.debug("BINARY2HOSTNAME successfully decoded custom host from binary: " + decodedHost);
                            break; 
                        }
                    } catch (decodeErr) {
                        console.debug("BINARY2HOSTNAME: Native stream decode failed, checking last-resort fallback...", decodeErr);
                    }
                }

                if (options.hasOwnProperty("uriStem") && options.uriStem) {
                    try {
                        let cleanStem = options.uriStem.replace(/^https?:\/\//i, '').split('/')[0];
                        if (cleanStem) {
                            internalMap[rule.newFieldName] = cleanStem;
                            console.debug("BINARY2HOSTNAME: Fell back to URI Stem Base parameter: " + cleanStem);
                        }
                    } catch (stemError) {
                        throw new Error("BINARY2HOSTNAME failed parsing last-resort fallback from uriStem: " + stemError.toString());
                    }
                } else {
                    throw new Error("BINARY2HOSTNAME failed: Bitstream unparseable and no default URI Stem Base option provided.");
                }
                break;
            }
            case "URLENCODE": {
                let encoded = '';
                for (let argVal of argVals) {
                    for (let i = 0; i < argVal.length; i++) {
                        if (TDTtranslator.regexURIEscapeChar.test(argVal.charAt(i))) {
                            encoded += '%';
                            encoded += argVal.charCodeAt(i).toString(16).toUpperCase().padStart(2, "0");
                        } else {
                            encoded += argVal.charAt(i);
                        }
                    }
                }
                internalMap[rule.newFieldName] = encoded;
                break;
            }
            case "URNDECODE":
            case "URLDECODE": {
                internalMap[rule.newFieldName] = decodeURIComponent(argVals);
                break;
            }
            case "CONCAT": {
                internalMap[rule.newFieldName] = argVals.join('');
                break;
            }
            case "SUBSTR": {
                if (typeof(argVals[0]) != "string") {
                    argVals[0] = argVals[0].toString()
                }
                if (argVals.length == 2) {
                    internalMap[rule.newFieldName] = argVals[0].substr(argVals[1])
                } else {
                    internalMap[rule.newFieldName] = argVals[0].substr(argVals[1], argVals[2])
                }
                break;
            }
            case "GS1CHECKSUM": {
                internalMap[rule.newFieldName] = TDTtranslator.calculateGS1CheckDigit(argVals[0]);
                break;
            }
            case "URNENCODE": {
                let encoded = '';
                for (let argVal of argVals) {
                    for (let i = 0; i < argVal.length; i++) {
                        if (TDTtranslator.regexURNEscapeChar.test(argVal.charAt(i))) {
                            encoded += '%';
                            encoded += argVal.charCodeAt(i).toString(16).toUpperCase().padStart(2, "0");
                        } else {
                            encoded += argVal.charAt(i);
                        }
                    }
                }
                internalMap[rule.newFieldName] = encoded;
                break;
            }
        }
    }

    // ------------------------------------------------------------------------
    // HIGH-TIER ARCHITECTURE STRUCTURE SYNTAX FORMATTERS
    // ------------------------------------------------------------------------
    
    static jsonPreFormat(string, aiSequence) {
        let parsed = JSON.parse(string);
        let formatted = '{';

        for (let ai of aiSequence) {
            if (ai in parsed) {
                formatted += '"' + ai + '":"' + parsed[ai] + '",';
                delete parsed[ai];
            } else {
                return "";
            }
        }

        for (let ai in parsed) {
            formatted += '"' + ai + '":"' + parsed[ai] + '",';
        }
        formatted = formatted.slice(0, -1) + "}";
        console.debug("Pre-formatted JSON " + formatted)
        return formatted;
    }

    static digitalLinkPreFormat(string, aiSequence) {
        let extra = [];
        let aiNum = 0;
        const urlRegex = /(https?:\/\/[^/]+)\/([^?]+\??)(.*)/;
        const stemRegex = /([0-9]{2,4})\/([^/?]+)[/?]?(.*)/;
        const optRegex = /([0-9]{2,4})=([^&]+)&?(.*)/;

        let split = urlRegex.exec(string);
        if (!split || split.length < 4) {
            return "";
        }

        let formatted = split[1];
        while (split[2].length > 0) {
            let aiPair = stemRegex.exec(split[2]);
            if (!aiPair || aiPair.length < 4) {
                return "";
            }
            if ((aiNum < aiSequence.length) && aiPair[1] == aiSequence[aiNum]) {
                formatted += '/' + aiPair[1] + '/' + aiPair[2];
                aiNum++;
            } else {
                extra[aiPair[1]] = aiPair[2];
            }
            split[2] = aiPair[3];
        }

        let sep = '?';

        while (split[3].length > 0) {
            let aiPair = optRegex.exec(split[3]);
            if (!aiPair || aiPair.length < 4) {
                return "";
            }
            if ((aiNum < aiSequence.length) && aiPair[1] == aiSequence[aiNum]) {
                formatted += sep + aiPair[1] + '=' + aiPair[2];
                aiNum++;
                sep = '&';
            } else {
                extra[aiPair[1]] = aiPair[2];
            }
            split[3] = aiPair[3];
        }

        for (let ai in extra) {
            formatted += sep + ai + '=' + extra[ai];
            sep = '&';
        }
        console.debug("Pre-formatted URI " + formatted)
        return formatted;
    }

    static digitalLinkPostFormat(string, keyQualifiers) {
        let found = [];
        const urlRegex = /(https?:\/\/[^/]+\/[0-9]{2,4}\/[^/?]+)\/?([^?]*)\??(.*)/;
        const stemRegex = /([0-9]{2,4})\/([^/]+)[/?]?(.*)/;
        const optRegex = /([0-9]{2,4})=([^&]+)&?(.*)/;

        let split = urlRegex.exec(string);
        if (!split || split.length < 4) {
            return "";
        }

        let formatted = split[1];

        while (split[2].length > 0) {
            let aiPair = stemRegex.exec(split[2]);
            if (!aiPair || aiPair.length < 4) {
                return "";
            }
            found[aiPair[1]] = aiPair[2];
            split[2] = split[2].substring(aiPair[0].length);
        }

        let options = "";
        let sep = "?";
        while (split[3].length > 0) {
            let aiPair = optRegex.exec(split[3]);
            if (!aiPair || aiPair.length < 4) {
                return "";
            }
            if (keyQualifiers.includes(aiPair[1])) {
                found[aiPair[1]] = aiPair[2];
            } else {
                options += sep + aiPair[1] + "=" + aiPair[2];
                sep = '&';
            }
            split[3] = split[3].substring(aiPair[0].length);
        }

        for (var aiNum = 0; aiNum < keyQualifiers.length; aiNum++) {
            if (keyQualifiers[aiNum] in found) {
                formatted += '/' + keyQualifiers[aiNum] + '/' + found[keyQualifiers[aiNum]];
            }
        }

        formatted += options;
        console.debug("Post-formatted URI " + formatted)
        return formatted;
    }

    static prePad(string, padCharacter, finalLength) {
        if (string.length < finalLength) {
            string = padCharacter.repeat(finalLength - string.length) + string;
        }
        return string;
    }

    static postPad(string, padCharacter, finalLength) {
        if (string.length < finalLength) {
            string += padCharacter.repeat(finalLength - string.length);
        }
        return string;
    }

    // ------------------------------------------------------------------------
    // PRIMITIVE COMPACTION DIGEST ENCODERS (TDS SYSTEM BLOCK ENGINES)
    // ------------------------------------------------------------------------
    
    static toBinaryUsingTruncatedASCII(inputCharacterString, bitsPerChr) {
        if (inputCharacterString === "") return "";

        const validBitsPerChr = [5, 6, 7, 8];
        if (!validBitsPerChr.includes(bitsPerChr)) {
            throw new Error(`Invalid bits per character: ${bitsPerChr}`);
        }

        let outputBinaryString = "";
        for (let i = 0; i < inputCharacterString.length; i++) {
            const charCode = inputCharacterString.charCodeAt(i);
            const binaryCharCode = charCode.toString(2).padStart(8, "0").substr(8 - bitsPerChr);
            outputBinaryString += binaryCharCode;
        }

        return outputBinaryString;
    }

    static fromBinaryUsingTruncatedASCII(inputBinaryString, bitsPerChr) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        if (![5, 6, 7, 8].includes(bitsPerChr)) {
            throw new Error(`Invalid bits per character: ${bitsPerChr}`);
        }

        let outputCharacterString = "";
        for (let i = 0; i < inputBinaryString.length; i += bitsPerChr) {
            const chunk = inputBinaryString.substr(i, bitsPerChr);
            let charCode = parseInt(chunk, 2);
            if ((bitsPerChr == 6 && charCode < 32) || bitsPerChr == 5) {
                charCode += 64;
            }
            if (charCode < 32) break;
            outputCharacterString += String.fromCharCode(charCode);
        }

        return outputCharacterString;
    }

    static toBinaryUsingFixedBitLengthInteger(inputCharacterString, options) {
        if (inputCharacterString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexAllNumeric.test(inputCharacterString)) {
            throw new Error("input " + inputCharacterString + " does not match regex for all-numeric strings");
        }

        const binary = BigInt(inputCharacterString).toString(2);

        if (binary.length > options.fixLenBits) {
            throw new Error("input " + inputCharacterString + " cannot be encoded within fixed bit count of " + options.fixLenBits + " bits");
        }

        return TDTtranslator.prePad(binary, "0", options.fixLenBits);
    }

    static fromBinaryUsingFixedBitLengthInteger(inputBinaryString, options) {
        if (inputBinaryString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("input " + inputBinaryString + " is not binary - only bit 0 or 1 allowed");
        }

        if (inputBinaryString.length < options.fixLenBits) {
            throw new Error("input " + inputBinaryString + " does not match expected length of " + options.fixLenBits + " bits");
        }

        return {
            "decoded": TDTtranslator.prePad(BigInt('0b' + inputBinaryString.substring(0, options.fixLenBits)).toString(), "0", options.fixLenChrs),
            "used": options.fixLenBits
        };
    }

    static toBinaryUsingPrioritisedDate(inputAIkey, inputYYMMDD) {
        if (TDTtranslator.regexAIkeyPrioritisedDate.test(inputAIkey)) {
            if (TDTtranslator.regexDateYYMMDD.test(inputYYMMDD)) {
                return TDTtranslator.fromAItoPrioritisedDateIndicator[inputAIkey] + TDTtranslator.toBinaryUsingDateYYMMDD(inputYYMMDD);
            } else {
                throw new Error("Input date " + inputYYMMDD + " does not match regex for a YYMMDD date value");
            }
        } else {
            throw new Error("Input AI (" + inputAIkey + ") does not match regex for a GS1 Application Identifier that can be used with a prioritised date within DSGTIN+");
        }
    }

    static fromBinaryUsingPrioritisedDate(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        if (inputBinaryString.length < 20) {
            throw new Error(`Input string must be 20 bits for method fromBinaryUsingPrioritisedDate`);
        }

        const prioritisedDateIndicator = inputBinaryString.substr(0, 4);
        const binaryDateValue = inputBinaryString.substr(4, 16);

        return {
            "AI": TDTtranslator.fromPrioritisedDateIndicatorToAI[prioritisedDateIndicator],
            "decoded": TDTtranslator.fromBinaryUsingDateYYMMDD(binaryDateValue).decoded,
            "used": 20
        };
    }

    static toBinaryUsingFixedLengthNumeric(inputCharacterString) {
        let outputBinaryString = "";
        for (let t = 0; t < inputCharacterString.length; t++) {
            const value = parseInt(inputCharacterString.charAt(t));
            outputBinaryString += TDTtranslator.prePad(value.toString(2), "0", 4);
        }
        return outputBinaryString;
    }

    static fromBinaryUsingFixedLengthNumeric(inputBinaryString, options) {
        let outputCharacterString = "";
        if (inputBinaryString.length < options.fixLenBits) {
            throw new Error(`Input string must be ` + options.fixLenBits + 'bits');
        }
        for (let t = 0; t < options.fixLenBits; t += 4) {
            const binarySubstring = inputBinaryString.substr(t, 4);
            const decimal = parseInt(binarySubstring, 2);
            outputCharacterString += decimal.toString(10);
        }
        return {
            "decoded": outputCharacterString,
            "used": options.fixLenBits
        };
    }

    static toBinaryUsingDelimitedNumeric(inputCharacterString, options) {
        let outputBinaryString = "";
        let t = 0;
        for (t = 0; t < inputCharacterString.length; t++) {
            const value = parseInt(inputCharacterString.charAt(t));
            if (isNaN(value)) {
                break;
            } else {
                outputBinaryString += TDTtranslator.prePad(value.toString(2), "0", 4);
            }
        }
        if (t < inputCharacterString.length) {
            outputBinaryString += "1110";
            outputBinaryString += TDTtranslator.toBinaryUsingVariableLengthAlphanumeric(inputCharacterString.substr(t), options);
        } else {
            outputBinaryString += "1111";
        }
        return outputBinaryString;
    }

    static fromBinaryUsingDelimitedNumeric(inputBinaryString, options) {
        let outputCharacterString = "";
        let used = 0;
        let t = 0;
        for (t = 0; t < inputBinaryString.length; t += 4) {
            const binarySubstring = inputBinaryString.substr(t, 4);
            const decimal = parseInt(binarySubstring, 2);
            used += 4;
            if (decimal <= 9) {
                outputCharacterString += decimal.toString(10);
            } else if (decimal == 15) {
                if ((t + 4) < inputBinaryString.length) {
                    throw new Error("inputBinaryString contains extra data beyond terminator");
                }
                break;
            } else if (decimal == 14) {
                t += 4;
                if (t >= inputBinaryString.length) {
                    throw new Error("inputBinaryString missing extra data beyond delimiter");
                }
                let extra = TDTtranslator.fromBinaryUsingVariableLengthAlphanumeric(inputBinaryString.substr(t), options);
                outputCharacterString += extra.decoded;
                used += extra.used;
                break;
            }
        }
        return {
            "decoded": outputCharacterString,
            "used": used
        };
    }

    static toBinaryUsingBigInteger(inputCharacterString) {
        if (inputCharacterString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexAllNumeric.test(inputCharacterString)) {
            throw new Error("input " + inputCharacterString + " does not match regex for all-numeric");
        }

        const bitLength = Math.ceil(Math.log2(Math.pow(10, inputCharacterString.length) - 1));
        const binary = BigInt(inputCharacterString).toString(2);

        return TDTtranslator.prePad(binary, "0", bitLength);
    }

    static fromBinaryUsingBigInteger(inputBinaryString) {
        if (inputBinaryString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("input " + inputBinaryString + " is not binary - only bit 0 or 1 allowed");
        }

        return BigInt('0b' + inputBinaryString).toString();
    }

    static toBinaryUsingUpperCaseHexadecimal(inputCharacterString) {
        if (!TDTtranslator.regexUpperCaseHexadecimal.test(inputCharacterString)) {
            throw new Error(`Input ${inputCharacterString} does not match regex for upper case hexadecimal`);
        }

        let outputBinaryString = "";
        for (let t = 0; t < inputCharacterString.length; t++) {
            const index = TDTtranslator.alphabetUpperCaseHexadecimal.indexOf(inputCharacterString.charAt(t));
            const binary = TDTtranslator.prePad(index.toString(2), "0", 4);
            outputBinaryString += binary;
        }
        return outputBinaryString;
    }

    static fromBinaryUsingUpperCaseHexadecimal(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        let outputCharacterString = "";
        if (inputBinaryString.length % 4 === 0) {
            for (let t = 0; t < inputBinaryString.length; t += 4) {
                const binarySubstring = inputBinaryString.substr(t, 4);
                const decimal = parseInt(binarySubstring, 2);
                outputCharacterString += TDTtranslator.alphabetUpperCaseHexadecimal.charAt(decimal);
            }
            return outputCharacterString;
        } else {
            throw new Error("Input is not an exact multiple of 4 bits");
        }
    }

    static toBinaryUsingLowerCaseHexadecimal(inputCharacterString) {
        if (!TDTtranslator.regexLowerCaseHexadecimal.test(inputCharacterString)) {
            throw new Error(`Input ${inputCharacterString} does not match regex for Lower case hexadecimal`);
        }

        let outputBinaryString = "";
        for (let t = 0; t < inputCharacterString.length; t++) {
            const index = TDTtranslator.alphabetLowerCaseHexadecimal.indexOf(inputCharacterString.charAt(t));
            const binary = TDTtranslator.prePad(index.toString(2), "0", 4);
            outputBinaryString += binary;
        }
        return outputBinaryString;
    }

    static fromBinaryUsingLowerCaseHexadecimal(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        let outputCharacterString = "";
        if (inputBinaryString.length % 4 === 0) {
            for (let t = 0; t < inputBinaryString.length; t += 4) {
                const binarySubstring = inputBinaryString.substr(t, 4);
                const decimal = parseInt(binarySubstring, 2);
                outputCharacterString += TDTtranslator.alphabetLowerCaseHexadecimal.charAt(decimal);
            }
            return outputCharacterString;
        } else {
            throw new Error("Input is not an exact multiple of 4 bits");
        }
    }

    static toBinaryUsingFileSafeURISafeBase64(inputCharacterString) {
        if (!TDTtranslator.regexFileSafeURISafeBase64.test(inputCharacterString)) {
            throw new Error(`Input ${inputCharacterString} does not match regex for file-safe URI-safe base 64`);
        }

        let outputBinaryString = "";
        for (let t = 0; t < inputCharacterString.length; t++) {
            const index = TDTtranslator.alphabetFileSafeURISafeBase64.indexOf(inputCharacterString.charAt(t));
            const binary = TDTtranslator.prePad(index.toString(2), "0", 6);
            outputBinaryString += binary;
        }
        return outputBinaryString;
    }

    static fromBinaryUsingFileSafeURISafeBase64(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        let outputCharacterString = "";
        if (inputBinaryString.length % 6 === 0) {
            for (let t = 0; t < inputBinaryString.length; t += 6) {
                const binarySubstring = inputBinaryString.substr(t, 6);
                const decimal = parseInt(binarySubstring, 2);
                outputCharacterString += TDTtranslator.alphabetFileSafeURISafeBase64.charAt(decimal);
            }
            return outputCharacterString;
        } else {
            throw new Error("Input is not an exact multiple of 6 bits");
        }
    }

    static toBinaryUsingURNcode40(inputCharacterString) {
        let outputBinaryString = "";
        if (TDTtranslator.regexURNcode40.test(inputCharacterString)) {
            if (inputCharacterString.length % 3 > 0) {
                inputCharacterString += " ".repeat(3 - (inputCharacterString.length % 3));
            }
            for (let t = 0; t < inputCharacterString.length / 3; t++) {
                const i1 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t));
                const i2 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 1));
                const i3 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 2));
                const b = TDTtranslator.prePad(((1600 * i1 + 40 * i2 + i3 + 1) >>> 0).toString(2), "0", 16);
                outputBinaryString += b;
            }
            return outputBinaryString;
        } else {
            throw new Error(`Input ${inputCharacterString} does not match regex for URN Code 40`);
        }
    }

    static fromBinaryUsingURNcode40(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("input is not binary - only bit 0 or 1 allowed");
        }

        let outputCharacterString = "";
        if (inputBinaryString.length % 16 == 0) {
            for (let t = 0; t < (inputBinaryString.length / 16); t++) {
                const substr = inputBinaryString.substr(16 * t, 16);
                const n = parseInt(substr, 2);
                const c3 = (n - 1) % 40;
                const c2 = (((n - 1) - c3) / 40) % 40;
                const c1 = (n - 1 - c3 - 40 * c2) / 1600;
                outputCharacterString += TDTtranslator.alphabetURNcode40.charAt(c1) + TDTtranslator.alphabetURNcode40.charAt(c2) + TDTtranslator.alphabetURNcode40.charAt(c3);
            }
            outputCharacterString = outputCharacterString.split(" ").join("");
            return outputCharacterString;
        } else {
            throw new Error("Input is not an exact multiple of 16 bits");
        }
    }

    static toBinaryUsingSevenBitASCII(inputCharacterString) {
        return TDTtranslator.toBinaryUsingTruncatedASCII(inputCharacterString, 7);
    }

    static fromBinaryUsingSevenBitASCII(inputBinaryString) {
        return TDTtranslator.fromBinaryUsingTruncatedASCII(inputBinaryString, 7);
    }

    static get encodingOptionsAlphanumeric() {
        return [
            {"regex":TDTtranslator.regexSevenBit, "indicator": "100","text":"7-bit ASCII","num":7,"denom":1,"encoder": TDTtranslator.toBinaryUsingSevenBitASCII ,"decoder": TDTtranslator.fromBinaryUsingSevenBitASCII},
            {"regex":TDTtranslator.regexFileSafeURISafeBase64, "indicator": "011","text":"file-safe URI-safe base 64","num":6,"denom":1,"encoder": TDTtranslator.toBinaryUsingFileSafeURISafeBase64,"decoder": TDTtranslator.fromBinaryUsingFileSafeURISafeBase64},
            {"regex":TDTtranslator.regexLowerCaseHexadecimal, "indicator": "010","text":"lower case hexadecimal","num":4,"denom":1,"encoder": TDTtranslator.toBinaryUsingLowerCaseHexadecimal ,"decoder": TDTtranslator.fromBinaryUsingLowerCaseHexadecimal},
            {"regex":TDTtranslator.regexUpperCaseHexadecimal, "indicator": "001","text":"upper case hexadecimal","num":4,"denom":1,"encoder": TDTtranslator.toBinaryUsingUpperCaseHexadecimal ,"decoder": TDTtranslator.fromBinaryUsingUpperCaseHexadecimal},
            {"regex":TDTtranslator.regexAllNumeric, "indicator": "000","text":"All-numeric","num":Math.log(10),"denom":Math.log(2),"encoder": TDTtranslator.toBinaryUsingBigInteger,"decoder": TDTtranslator.fromBinaryUsingBigInteger},
            {"regex":TDTtranslator.regexURNcode40, "indicator": "101","text":"URN Code 40","num":16,"denom": 3,"encoder": TDTtranslator.toBinaryUsingURNcode40,"decoder": TDTtranslator.fromBinaryUsingURNcode40}
        ];
    }

    static byAscendingBitCount(a, b) {
        if (a.bitCount < b.bitCount) { return -1; }
        if (a.bitCount > b.bitCount) { return 1; }
        return a.indicator > b.indicator ? 1 : -1 ;
    }

    static toBinaryUsingVariableLengthAlphanumeric(inputCharacterString, options) {
        let candidates = [];
        const length = inputCharacterString.length;

        for (let o of TDTtranslator.encodingOptionsAlphanumeric) {
            if (o.regex.test(inputCharacterString)) {
                let bitCount = 0;
                if (o.denom == 1) {
                    bitCount = Math.ceil(length * o.num);
                } else {
                    if (o.denom == 3) {
                        bitCount = Math.ceil(o.num * Math.ceil(length / o.denom));
                    } else {
                        bitCount = Math.ceil(o.num * length / o.denom);
                    }
                }
                candidates.push({"indicator": o.indicator, "text": o.text, "bitCount": bitCount, "encoder": o.encoder});
            }
        }

        if (candidates.length == 0 ) {
            throw new Error("No viable encoding option found for " + JSON.stringify(inputCharacterString) + " - check for non-encodable characters.");
        }

        let sortedCandidates = candidates.sort(TDTtranslator.byAscendingBitCount);
        let mostEfficientEncoding = sortedCandidates[0];
        console.debug("Using encoding " + mostEfficientEncoding.text);
        return mostEfficientEncoding.indicator + TDTtranslator.prePad(length.toString(2), "0", options.lenIndBits) + mostEfficientEncoding.encoder(inputCharacterString);
    }

    static fromBinaryUsingVariableLengthAlphanumeric(inputBinaryString, options) {
        let rv = {};
        rv.used = 0;

        if ((inputBinaryString !== undefined) && (TDTtranslator.regexBinaryString.test(inputBinaryString))) {
            let encodingIndicator = inputBinaryString.substr(0, 3);
            rv.used += 3;
            let length = parseInt(inputBinaryString.substr(3, options.lenIndBits), 2);
            rv.used += options.lenIndBits;

            let decodingOption = TDTtranslator.encodingOptionsAlphanumeric.filter(TDTtranslator.matchEncodingIndicator(encodingIndicator))[0];
            let bitCount = 0;

            if (decodingOption.denom == 1) {
                bitCount = Math.ceil(length * decodingOption.num);
            } else {
                if (decodingOption.denom == 3) {
                    bitCount = Math.ceil(decodingOption.num * Math.ceil(length / decodingOption.denom));
                } else {
                    bitCount = Math.ceil(decodingOption.num * length / decodingOption.denom);
                }
            }

            let binaryValue = inputBinaryString.substr(rv.used, bitCount);
            rv.used += bitCount;
            rv.decoded = TDTtranslator.prePad(decodingOption.decoder(binaryValue), "0", length);
            return rv;

        } else {
            if (inputBinaryString == undefined) {
                throw new Error("input string is undefined");
            } else {
                throw new Error(inputBinaryString + " is not binary - only bit 0 or 1 allowed");
            }
        }
    }

    static toBinaryUsingSingleDataBit(inputCharacterString) {
        if (!TDTtranslator.regexSingleBit.test(inputCharacterString)) {
            throw new Error(`Input ${inputCharacterString} does not match regex for a single bit (0 or 1)`);
        }
        return inputCharacterString;
    }

    static fromBinaryUsingSingleDataBit(inputBinaryString) {
        if (!TDTtranslator.regexSingleBit.test(inputBinaryString.substr(0, 1))) {
            throw new Error(`Input ${inputBinaryString} does not match regex for a single bit (0 or 1)`);
        }
        return {
            "decoded": inputBinaryString.substr(0, 1),
            "used": 1
        };
    }

    static toBinaryUsingDateYYMMDD(inputYYMMDD) {
        if (!TDTtranslator.regexDateYYMMDD.test(inputYYMMDD)) {
            throw new Error(`Input ${inputYYMMDD} does not match regex for date YYMMDD`);
        }

        const yy = parseInt(inputYYMMDD.substr(0, 2)).toString(2).padStart(7, "0");
        const mm = parseInt(inputYYMMDD.substr(2, 2)).toString(2).padStart(4, "0");
        const dd = parseInt(inputYYMMDD.substr(4, 2)).toString(2).padStart(5, "0");

        return yy + mm + dd;
    }

    static fromBinaryUsingDateYYMMDD(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        if (inputBinaryString.length < 16) {
            throw new Error("Input string must be 16 bits");
        }

        const yy = parseInt(inputBinaryString.substr(0, 7), 2);
        const mm = parseInt(inputBinaryString.substr(7, 4), 2);
        const dd = parseInt(inputBinaryString.substr(11, 5), 2);

        if (yy > 99) {
            throw new Error("Input string must not encode a YY year value > 99");
        }

        if (mm < 1 || mm > 12) {
            throw new Error("Input string must not encode a MM month value < 1 or > 12");
        }

        if (dd < 1) {
            throw new Error("Input string must not encode a DD day value < 1");
        }

        return {
            "decoded": yy.toString().padStart(2, "0") + mm.toString().padStart(2, "0") + dd.toString().padStart(2, "0"),
            "used": 16
        };
    }

    static toBinaryUsingDateYYMMDDhhmm(inputYYMMDDhhmm) {
        if (!TDTtranslator.regexDateYYMMDDhhmm.test(inputYYMMDDhhmm)) {
            throw new Error(`Input ${inputYYMMDDhhmm} does not match regex for date YYMMDDhhmm`);
        }

        const yy = parseInt(inputYYMMDDhhmm.substr(0, 2)).toString(2).padStart(7, "0");
        const mm = parseInt(inputYYMMDDhhmm.substr(2, 2)).toString(2).padStart(4, "0");
        const dd = parseInt(inputYYMMDDhhmm.substr(4, 2)).toString(2).padStart(5, "0");
        const hh = parseInt(inputYYMMDDhhmm.substr(6, 2)).toString(2).padStart(5, "0");
        const nn = parseInt(inputYYMMDDhhmm.substr(8, 2)).toString(2).padStart(6, "0");

        return yy + mm + dd + hh + nn;
    }

    static fromBinaryUsingDateYYMMDDhhmm(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only bit 0 or 1 allowed");
        }

        if (inputBinaryString.length < 27) {
            throw new Error("Input string must be 27 bits");
        }

        const yy = parseInt(inputBinaryString.substr(0, 7), 2);
        const mm = parseInt(inputBinaryString.substr(7, 4), 2);
        const dd = parseInt(inputBinaryString.substr(11, 5), 2);
        const hh = parseInt(inputBinaryString.substr(16, 5), 2);
        const nn = parseInt(inputBinaryString.substr(21, 6), 2);

        if (yy > 99) {
            throw new Error("Input string must not encode a YY year value > 99");
        }

        if (mm < 1 || mm > 12) {
            throw new Error("Input string must not encode a MM month value < 1 or > 12");
        }

        if (dd < 1) {
            throw new Error("Input string must not encode a DD day value < 1");
        }

        if (hh > 24) {
            throw new Error("Input string must not encode a hh hour value > 24");
        }

        if (nn > 59) {
            throw new Error("Input string must not encode a mm minute value > 59");
        }

        return {
            "decoded": yy.toString().padStart(2, "0") + mm.toString().padStart(2, "0") + dd.toString().padStart(2, "0") +
                hh.toString().padStart(2, "0") + nn.toString().padStart(2, "0"),
            "used": 27
        };
    }

    static toBinaryUsingDateOrDateRange(inputYYMMDDorYYMMDDYYMMDD) {
        if (inputYYMMDDorYYMMDDYYMMDD === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexDateYYMMDDorYYMMDDYYMMDD.test(inputYYMMDDorYYMMDDYYMMDD)) {
            throw new Error("input " + inputYYMMDDorYYMMDDYYMMDD + " does not match regex for date YYMMDD or date range YYMMDDYYMMDD");
        }

        const y1 = inputYYMMDDorYYMMDDYYMMDD.substr(0, 2);
        const m1 = inputYYMMDDorYYMMDDYYMMDD.substr(2, 2);
        const d1 = inputYYMMDDorYYMMDDYYMMDD.substr(4, 2);
        if (inputYYMMDDorYYMMDDYYMMDD.length === 6) {
            return "0" + TDTtranslator.prePad(parseInt(y1).toString(2), "0", 7) + TDTtranslator.prePad(parseInt(m1).toString(2), "0", 4) + TDTtranslator.prePad(parseInt(d1).toString(2), "0", 5);
        } else {
            const y2 = inputYYMMDDorYYMMDDYYMMDD.substr(6, 2);
            const m2 = inputYYMMDDorYYMMDDYYMMDD.substr(8, 2);
            const d2 = inputYYMMDDorYYMMDDYYMMDD.substr(10, 2);
            return "1" + TDTtranslator.prePad(parseInt(y1).toString(2), "0", 7) + TDTtranslator.prePad(parseInt(m1).toString(2), "0", 4) + TDTtranslator.prePad(parseInt(d1).toString(2), "0", 5) + TDTtranslator.prePad(parseInt(y2).toString(2), "0", 7) + TDTtranslator.prePad(parseInt(m2).toString(2), "0", 4) + TDTtranslator.prePad(parseInt(d2).toString(2), "0", 5);
        }
    }

    static fromBinaryUsingDateOrDateRange(inputBinaryString) {
        if (inputBinaryString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error(inputBinaryString + " is not binary - only bit 0 or 1 allowed");
        }

        const isDateRange = inputBinaryString.charAt(0) === '1';

        if (inputBinaryString.length < (isDateRange ? 33 : 17)) {
            throw new Error("input string must be " + (isDateRange ? 33 : 17) + " bits for method fromBinaryUsingDateOrDateRange");
        }

        const yy1 = parseInt(inputBinaryString.substr(1, 7), 2);
        const mm1 = parseInt(inputBinaryString.substr(8, 4), 2);
        const dd1 = parseInt(inputBinaryString.substr(12, 5), 2);

        if (yy1 > 99) {
            throw new Error("input string must not encode a YY year value > 99");
        }

        if (mm1 < 1 || mm1 > 12) {
            throw new Error("input string must not encode a MM month value < 1 or > 12");
        }

        if (dd1 < 1) {
            throw new Error("input string must not encode a DD day value < 1");
        }

        let result = TDTtranslator.prePad(yy1.toString(), "0", 2) + TDTtranslator.prePad(mm1.toString(), "0", 2) + TDTtranslator.prePad(dd1.toString(), "0", 2);

        if (isDateRange) {
            const yy2 = parseInt(inputBinaryString.substr(17, 7), 2);
            const mm2 = parseInt(inputBinaryString.substr(24, 4), 2);
            const dd2 = parseInt(inputBinaryString.substr(28, 5), 2);

            if (yy2 > 99) {
                throw new Error("input string must not encode a YY year value > 99; end YY value in date range = " + yy2);
            }

            if (mm2 < 1 || mm2 > 12) {
                throw new Error("input string must not encode a MM month value < 1 or > 12; end MM value in date range = " + mm2);
            }

            if (dd2 < 1) {
                throw new Error("input string must not encode a DD day value < 1; end DD day value in date range = " + dd2);
            }

            result += TDTtranslator.prePad(yy2.toString(), "0", 2) + TDTtranslator.prePad(mm2.toString(), "0", 2) + TDTtranslator.prePad(dd2.toString(), "0", 2);
        }

        return {
            "decoded": result,
            "used": (isDateRange ? 33 : 17)
        };
    }

    static toBinaryUsingVariablePrecisionDateTime(inputYYMMDDhh_mmss) {
        if (!TDTtranslator.regexVariablePrecisionDateTimeYYMMDDhh_mmss.test(inputYYMMDDhh_mmss)) {
            throw new Error(`Input ${inputYYMMDDhh_mmss} does not match regex for variable-precision date+time YYMMDD[hh][mm][ss]`);
        }

        const length = inputYYMMDDhh_mmss.length;
        let binaryString = "";

        if (length === 8) {
            binaryString = "00";
        } else if (length === 10) {
            binaryString = "01";
        } else if (length === 12) {
            binaryString = "10";
        } else if (length === 6) {
            binaryString = "11";
        }

        const yy = parseInt(inputYYMMDDhh_mmss.substr(0, 2), 10).toString(2).padStart(7, "0");
        const mm = parseInt(inputYYMMDDhh_mmss.substr(2, 2), 10).toString(2).padStart(4, "0");
        const dd = parseInt(inputYYMMDDhh_mmss.substr(4, 2), 10).toString(2).padStart(5, "0");
        let hh = "";
        let nn = "";
        let ss = "";

        if (length > 6) {
            hh = parseInt(inputYYMMDDhh_mmss.substr(6, 2), 10).toString(2).padStart(5, "0");
        }

        if (length >= 10) {
            nn = parseInt(inputYYMMDDhh_mmss.substr(8, 2), 10).toString(2).padStart(6, "0");
        }

        if (length === 12) {
            ss = parseInt(inputYYMMDDhh_mmss.substr(10, 2), 10).toString(2).padStart(6, "0");
        }

        return binaryString + yy + mm + dd + hh + nn + ss;
    }

    static fromBinaryUsingVariablePrecisionDateTime(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is undefined or not binary - only bit 0 or 1 allowed");
        }

        const length = inputBinaryString.length;

        if (length < 18) {
            throw new Error(`Input string must be at least 18 bits for method fromBinaryUsingVariablePrecisionDateTime`);
        }

        const prefix = inputBinaryString.substr(0, 2);
        const outputStrings = [];
        let used = 18;

        const yy = parseInt(inputBinaryString.substr(2, 7), 2);
        const mm = parseInt(inputBinaryString.substr(9, 4), 2);
        const dd = parseInt(inputBinaryString.substr(13, 5), 2);

        if (yy > 99) {
            throw new Error(`Input string must not encode a YY year value > 99; ${yy} found`);
        }

        if (mm < 1 || mm > 12) {
            throw new Error(`Input string must not encode a MM month value < 1 or > 12; ${mm} found`);
        }

        if (dd < 1) {
            throw new Error(`Input string must not encode a DD day value < 1; ${dd} found`);
        }
        outputStrings.push(`${yy.toString().padStart(2, "0")}${mm.toString().padStart(2, "0")}${dd.toString().padStart(2, "0")}`);

        if (prefix !== "11") {
            if (length < 23) {
                throw new Error(`Input string must be at least 23 bits for method YYMMMDDhh format fromBinaryUsingVariablePrecisionDateTime`);
            }
            const hh = parseInt(inputBinaryString.substr(18, 5), 2);
            if (hh > 24) {
                throw new Error(`Input string must not encode a hh hour value > 24; ${hh} found`);
            }
            outputStrings.push(`${hh.toString().padStart(2, "0")}`);
            used += 5;
        }

        if (prefix === "01" || prefix === "10") {
            if (length < 29) {
                throw new Error(`Input string must be at least 29 bits for method YYMMMDDhhmm format fromBinaryUsingVariablePrecisionDateTime`);
            }
            const nn = parseInt(inputBinaryString.substr(23, 6), 2);
            if (nn > 59) {
                throw new Error(`Input string must not encode a mm minute value > 59; ${nn} found`);
            }
            outputStrings.push(`${nn.toString().padStart(2, "0")}`);
            used += 6;
        }

        if (prefix === "10") {
            if (length < 36) {
                throw new Error(`Input string must be at least 36 bits for method YYMMMDDhhmmss format fromBinaryUsingVariablePrecisionDateTime`);
            }
            const ss = parseInt(inputBinaryString.substr(29, 6), 2);
            if (ss > 59) {
                throw new Error(`Input string must not encode a ss second value > 59`);
            }
            outputStrings.push(`${ss.toString().padStart(2, "0")}`);
            used += 6;
        }

        return {
            "decoded": outputStrings.join(""),
            "used": used
        };
    }

    static toBinaryUsingCountryCode(inputCountryCode) {
        if (inputCountryCode === undefined) {
            throw new Error("input string is undefined");
        }
        inputCountryCode = inputCountryCode.toUpperCase();
        if (TDTtranslator.regexCountryCode.test(inputCountryCode)) {
            return TDTtranslator.toBinaryUsingFileSafeURISafeBase64(inputCountryCode);
        } else {
            throw new Error("input " + inputCountryCode + " does not match regex for country code");
        }
    }

    static fromBinaryUsingCountryCode(inputBinaryString) {
        if (inputBinaryString === undefined) {
            throw new Error("input string is undefined");
        }
        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error(inputBinaryString + " is not binary - only bit 0 or 1 allowed");
        }
        if (inputBinaryString.length < 12) {
            throw new Error("input string must be 12 bits for method fromBinaryUsingCountryCode");
        }
        return {
            "decoded": TDTtranslator.fromBinaryUsingFileSafeURISafeBase64(inputBinaryString.substr(0, 12)),
            "used": 12
        };
    }

    static toBinaryUsingVariableLengthNumeric(inputCharacterString, options) {
        return TDTtranslator.prePad(inputCharacterString.length.toString(2), "0", options.lenIndBits) + TDTtranslator.toBinaryUsingBigInteger(inputCharacterString);
    }

    static fromBinaryUsingVariableLengthNumeric(inputBinaryString, options) {
        let length = parseInt(inputBinaryString.substr(0, options.lenIndBits), 2);
        const bitLength = Math.ceil(Math.log2(Math.pow(10, length) - 1));
        return {
            "decoded": TDTtranslator.prePad(TDTtranslator.fromBinaryUsingBigInteger(inputBinaryString.substr(options.lenIndBits, bitLength)), "0", length),
            "used": options.lenIndBits + bitLength
        };
    }

    static toBinaryUsingOptionalMinus(inputCharacterString) {
        if (!TDTtranslator.regexOptionalMinus.test(inputCharacterString)) {
            throw new Error(`Input ${inputCharacterString} does not match regex for optional minus ('-' or empty string)`);
        }
        return (inputCharacterString == "-") ? "1" : "0";
    }

    static fromBinaryUsingOptionalMinus(inputBinaryString) {
        if (!TDTtranslator.regexSingleBit.test(inputBinaryString.charAt(0))) {
            throw new Error(`Input ${inputBinaryString} does not match regex for a single bit (0 or 1)`);
        }
        return {
            "decoded": (inputBinaryString.charAt(0) == "1") ? "-" : "",
            "used": 1
        };
    }

    // ------------------------------------------------------------------------
    // TDS SECTION REFERENCE CAPABILITY ROUTINES LOOKUPS MAP
    // ------------------------------------------------------------------------
    static get tds2encodingMethods() {
        return {
            "14.5.2": { "regex": TDTtranslator.regexAllNumeric, "encoder": TDTtranslator.toBinaryUsingFixedBitLengthInteger, "decoder": TDTtranslator.fromBinaryUsingFixedBitLengthInteger },
            "14.5.3": {}, 
            "14.5.4": { "regex": TDTtranslator.regexAllNumeric, "encoder": TDTtranslator.toBinaryUsingFixedLengthNumeric, "decoder": TDTtranslator.fromBinaryUsingFixedLengthNumeric },
            "14.5.5": { "regex": TDTtranslator.regexAlphanumeric, "encoder": TDTtranslator.toBinaryUsingDelimitedNumeric, "decoder": TDTtranslator.fromBinaryUsingDelimitedNumeric },
            "14.5.6": { "regex": TDTtranslator.regexAlphanumeric, "encoder": TDTtranslator.toBinaryUsingVariableLengthAlphanumeric, "decoder": TDTtranslator.fromBinaryUsingVariableLengthAlphanumeric },
            "14.5.7": { "regex": TDTtranslator.regexSingleBit, "encoder": TDTtranslator.toBinaryUsingSingleDataBit, "decoder": TDTtranslator.fromBinaryUsingSingleDataBit },
            "14.5.8": { "regex": TDTtranslator.regexDateYYMMDD, "encoder": TDTtranslator.toBinaryUsingDateYYMMDD, "decoder": TDTtranslator.fromBinaryUsingDateYYMMDD },
            "14.5.9": { "regex": TDTtranslator.regexDateYYMMDDhhmm, "encoder": TDTtranslator.toBinaryUsingDateYYMMDDhhmm, "decoder": TDTtranslator.fromBinaryUsingDateYYMMDDhhmm },
            "14.5.10": { "regex": TDTtranslator.regexDateYYMMDDorYYMMDDYYMMDD, "encoder": TDTtranslator.toBinaryUsingDateOrDateRange, "decoder": TDTtranslator.fromBinaryUsingDateOrDateRange },
            "14.5.11": { "regex": TDTtranslator.regexVariablePrecisionDateTimeYYMMDDhh_mmss, "encoder": TDTtranslator.toBinaryUsingVariablePrecisionDateTime, "decoder": TDTtranslator.fromBinaryUsingVariablePrecisionDateTime},
            "14.5.12": { "regex": TDTtranslator.regexCountryCode, "encoder": TDTtranslator.toBinaryUsingCountryCode, "decoder": TDTtranslator.fromBinaryUsingCountryCode },
            "14.5.13": { "regex": TDTtranslator.regexAllNumeric, "encoder": TDTtranslator.toBinaryUsingVariableLengthNumeric, "decoder": TDTtranslator.fromBinaryUsingVariableLengthNumeric },
            "14.5.14": { "regex": TDTtranslator.regexOptionalMinus, "encoder": TDTtranslator.toBinaryUsingOptionalMinus, "decoder": TDTtranslator.fromBinaryUsingOptionalMinus }
        };
    }

    static toBinaryUsingTableF(inputCharacterString, options) {
        const rv = {};
        const isRawBitstream = /^[01]+$/.test(inputCharacterString) && inputCharacterString.length > 32;

        if (!isRawBitstream && (!isNaN(options.maxChars)) && (inputCharacterString.length > options.maxChars) ) {
            throw new Error("inputCharacterString '" + inputCharacterString + "' is longer than specified inputMaxLength (" + options.maxChars + ")");
        }
        if (!isRawBitstream && (!isNaN(options.fixLenChrs)) && (inputCharacterString.length != options.fixLenChrs)) {
            throw new Error("inputCharacterString '" + inputCharacterString + "' is not the specified length (" + options.fixLenChrs + ")");
        }
        if (!TDTtranslator.tds2encodingMethods[options.section]) {
            throw new Error("Encoding method not found for TDS section " + options.section);
        } else {
            rv.encodingMethod = TDTtranslator.tds2encodingMethods[options.section];

            if (!rv.encodingMethod.regex.test(inputCharacterString)) {
                throw new Error("inputCharacterString '" + inputCharacterString + "' does not match required ");
            }

            rv.binary = rv.encodingMethod.encoder(inputCharacterString, options);
            return rv;
        }
    }

    static fromBinaryUsingTableF(inputBinaryString, options) {
        const rv = {};

        if (!TDTtranslator.tds2encodingMethods[options.section]) {
            throw new Error("Encoding method not found for " + JSON.stringify(options.section));
        } else {
            rv.encodingMethod = TDTtranslator.tds2encodingMethods[options.section];
            let dec = rv.encodingMethod.decoder(inputBinaryString, options);
            rv.characterString = dec.decoded;
            rv.used = dec.used;
            return rv;
        }
    }

    // ------------------------------------------------------------------------
    // PURE FUNCTIONAL PLUSDATA EXTRACTORS AND ENCODERS
    // ------------------------------------------------------------------------
    
    static fromJSONExtractPlusData(inputJSONString, aiSequence) {
        const parsed = JSON.parse(inputJSONString);
        let plusData = [];

        for (let ai of Object.keys(parsed)) {
            if (aiSequence.includes(ai)) {
                continue;
            }
            plusData.push({"ai": ai, "value": parsed[ai]});
        }
        return plusData;
    }

    static fromBINARYExtractPlusData(inputBinaryString, tablef, tablek) {
        let plusData = [];

        if (inputBinaryString.length < 8) {
            return plusData;
        }
        while (inputBinaryString.length > 8) {
            let ai = parseInt(inputBinaryString.substr(0, 4), 2).toString();
            ai += parseInt(inputBinaryString.substr(4, 4), 2).toString();
            if (!/^[0-9]{2}$/.test(ai)) {
                throw new Error("Invalid decoded AI " + ai);
            }
            inputBinaryString = inputBinaryString.substr(8);

            if (ai == "00" && inputBinaryString.length < 72) return plusData;

            let tableKrow = tablek[ai];
            if (!tableKrow) {
                throw new Error("Invalid AI prefix decoded " + ai);
            }
            if (tableKrow.b > 2) {
                ai += parseInt(inputBinaryString.substr(0, 4), 2).toString();
                if (!/^[0-9]{3}$/.test(ai)) {
                    throw new Error("Invalid decoded AI " + ai);
                }
                inputBinaryString = inputBinaryString.substr(4);
                if (tableKrow.b > 3) {
                    ai += parseInt(inputBinaryString.substr(0, 4), 2).toString();
                    if (!/^[0-9]{4}$/.test(ai)) {
                        throw new Error("Invalid decoded AI " + ai);
                    }
                    inputBinaryString = inputBinaryString.substr(4);
                }
            }

            let tableFrow = tablef[ai];
            if (tableFrow) {
                let value = '';
                let decoded = TDTtranslator.fromBinaryUsingTableF(inputBinaryString, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });
                value += decoded.characterString;
                inputBinaryString = inputBinaryString.substr(decoded.used);
                if (tableFrow.j) {
                    let decoded = TDTtranslator.fromBinaryUsingTableF(inputBinaryString, { "section": tableFrow.j, "fixLenChrs" : parseInt(tableFrow.k), "fixLenBits": parseInt(tableFrow.l), "encIndBits": parseInt(tableFrow.m), "lenIndBits": parseInt(tableFrow.n), "maxChars": parseInt(tableFrow.o) });
                    value += decoded.characterString;
                    inputBinaryString = inputBinaryString.substr(decoded.used);
                }
                plusData.push({"ai": ai, "value": value});
            }
        }
        console.debug(JSON.stringify(plusData, null, 2))
        return plusData;
    }

    static fromDigitalLinkExtractPlusData(inputDLString) {
        let re = new RegExp(/^(([0-9]{2,4})=([A-Za-z0-9%"._-]+)(&|$)?)/);
        let matches = [];
        let plusData = [];
        while (matches = inputDLString.match(re)) {
            inputDLString = inputDLString.substr(matches[0].length);
            plusData.push({"ai": matches[2], "value": decodeURIComponent(matches[3])});
        }
        console.debug(JSON.stringify(plusData, null, 2))
        return plusData;
    }

    static toBINARYEncodePlusData(plusdata, tablef, returnArray) {
        let rv = [];
        let rvComponents = [];
        for (let data of plusdata) {
            let tableFrow = tablef[data.ai];
            if (tableFrow) {
                console.debug("TableF row for AI (" + data.ai + "): " + JSON.stringify(tableFrow,null,2));

                let aiBin = []
                for (let t = 0; t < data.ai.length; t++) {
                    aiBin.push(TDTtranslator.prePad(parseInt(data.ai.charAt(t)).toString(2), "0", 4))
                }
                rv.push(aiBin.join(""));
                rvComponents.push("AI " + data.ai + " identifier");

                let plusDataOutput = [];
                let componentCount = 1;
                console.debug("Using method " + tableFrow.b + " for encoding component " + componentCount + " as defined in TDS section " + tableFrow.c);

                let componentValue = data.value;
                if (tableFrow.j) {
                    componentValue = componentValue.substr(0, tableFrow.d)
                }
                let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });

                plusDataOutput.push(b.binary);

                if (tableFrow.j) {
                    componentCount ++;
                    componentValue = data.value.substr(tableFrow.d);
                    console.debug("Using method " + tableFrow.i + " for encoding component " + componentCount + " as defined in TDS section " + tableFrow.j);
                    let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.j, "fixLenChrs" : parseInt(tableFrow.k), "fixLenBits": parseInt(tableFrow.l), "encIndBits": parseInt(tableFrow.m), "lenIndBits": parseInt(tableFrow.n), "maxChars": parseInt(tableFrow.o) });
                    plusDataOutput.push(b.binary);
                }

                rv.push(plusDataOutput.join(""));
                rvComponents.push("AI " + data.ai + " data");
            }
        }
        if (returnArray) {
            return [rv, rvComponents];
        }
        return rv.join("");
    }

    static toJSONEncodePlusData(plusdata) {
        let encoded = "";
        for (let data of plusdata) {
            encoded += ',"' + data.ai + '":';
            let json = JSON.stringify(data.value);
            encoded += json;
        }
        return encoded;
    }

    static toDigitalLinkEncodePlusData(plusdata) {
        let encoded = [];
        for (let data of plusdata) {
            encoded.push (data.ai + "=" + encodeURIComponent(data.value));
        }
        return encoded.join("&");
    }

    // ------------------------------------------------------------------------
    // HIGH-LEVEL ROUTING & AUTO-DETECTION ENGINE
    // ------------------------------------------------------------------------
    
    handleCompressedDL(inputString, overridingURIstem) {
        const regexFileSafeURISafeBase64compressedDL = /^(https:\/\/.+?)\/ex([0-9A-Za-z_-]+)$/;
        const regexHexcompressedDL = /^(https:\/\/.+?)\/eh([0-9a-fA-F]+)$/;
        if ((regexFileSafeURISafeBase64compressedDL.test(inputString)) || (regexHexcompressedDL.test(inputString)) ) {
            let uriStem = "";
            if (overridingURIstem) overridingURIstem = overridingURIstem.replace(/\/$/,"");
                    
            if (regexFileSafeURISafeBase64compressedDL.test(inputString)) {
                let uriMatches = inputString.match(regexFileSafeURISafeBase64compressedDL);
                if ((uriMatches) && (uriMatches.hasOwnProperty('length')) && (uriMatches.length == 3)) {
                    inputString = TDTtranslator.toBinaryUsingFileSafeURISafeBase64(uriMatches[2]);
                    uriStem = uriMatches[1];
                }
            }
    
            if (regexHexcompressedDL.test(inputString)) {
                let uriMatches = inputString.match(regexHexcompressedDL);
                if ((uriMatches) && (uriMatches.hasOwnProperty('length')) && (uriMatches.length == 3)) {
                    inputString = this.hex2bin(uriMatches[2]);
                    uriStem = uriMatches[1];
                }
            }

            let detected = this.autodetect(inputString);
            if (detected && detected.length > 0) {
                let options = { "filter": 0, "uriStem": uriStem, "gs1companyprefixlength": -1 };
                let translated = null;
                for (let match of detected) {
                    translated = this.translate(inputString, match.scheme, "GS1_DIGITAL_LINK", options);
                }
                return (overridingURIstem || uriStem) + translated;
            } else {
                return "No match found";
            }
        } else {
            return inputString;
        }
    }
    
    autodetect(inputString) {
        if (!this.tdtData || !this.tdtData.scheme) {
             console.error('Data not available yet. Please wait for initialization.');
             return [];
        }

        let rv = []
        let isHex = false;
        if (TDTtranslator.regexHexadecimal.test(inputString) && !TDTtranslator.regexBinaryString.test(inputString)) {
            console.debug("Detected hex input");
            inputString = this.hex2bin(inputString);
            isHex = true;
        }
        for (let s of Object.keys(this.tdtData.scheme)) {
            let optionKey = this.tdtData.scheme[s][TDTtranslator.tdtDataContainer].scheme.optionKey
            let levels = [];
            for (let level of this.tdtData.scheme[s][TDTtranslator.tdtDataContainer].scheme.level) {
                levels.push(level.type);
            }
            for (let sl of this.tdtData.scheme[s][TDTtranslator.tdtDataContainer].scheme.level) {
                if (inputString.startsWith(sl.prefixMatch)) {
                    let testString = inputString;
                    for (let o of sl.option) {
                        switch (sl.type) {
                            case "GS1_AI_JSON": {
                                testString = TDTtranslator.jsonPreFormat(inputString, o.aiSequence);
                                break;
                            }
                            case "GS1_DIGITAL_LINK": {
                                testString = TDTtranslator.digitalLinkPreFormat(inputString, o.aiSequence);
                                break;
                            }
                        }
                        let re = new RegExp(o.pattern);
                        if (re.test(testString)) {
                            let prefixLen = -1;
                            switch (sl.type) {
                                case "GS1_DIGITAL_LINK":
                                case "GS1_AI_JSON":
                                case "BARE_IDENTIFIER": {
                                    let fields = re.exec(testString);
                                    let lookupString = fields[1];
                                
                                    if (sl.type === "GS1_AI_JSON") {
                                        lookupString = lookupString.replace(/[^0-9]/g, '');
                                    }
                                
                                    if (o.field[0].hasOwnProperty('gcpOffset')) {
                                        lookupString = lookupString.substring(o.field[0].gcpOffset);
                                    } else {
                                        if (["gtin", "itip", "sscc"].includes(o.field[0].name)) {
                                            if (lookupString.length === 14) {
                                                lookupString = lookupString.substring(1);
                                            }
                                        }
                                    }
                                    prefixLen = this.#lookupPrefixLength(lookupString);
                                    break;
                                }
                                case "BINARY":
                                case "TAG_ENCODING":
                                case "PURE_IDENTITY": {
                                    if (optionKey == "gs1companyprefixlength") prefixLen = parseInt(o.optionKey);
                                    break;
                                }
                            }

                            if (optionKey === "gs1companyprefixlength" && prefixLen !== -1 && prefixLen !== parseInt(o.optionKey)) {
                                continue; 
                            }
    
                            rv.push({"scheme":s,"level":(isHex && (sl.type == "BINARY") ? "HEX" : sl.type),"optionKey": {"property": optionKey, "value": o.optionKey}, "supportedLevels": levels, "detectedGCPLength": prefixLen});
                        }
                    }
                }
            }
        }
        return rv;
    }

    /**
     * Master Translation Runtime Orchestrator Loop.
     */
    translate(inputString, scheme, outputLevel, options = {}) {
        let internalMap = {};
        let outputLevelData = null;
        let hexOut = false;

        if (!this.tdtData || !this.tdtData.scheme) {
            throw new Error('System State Error: Engine processing called prior to data repository realization.');
        }

        console.debug("Request to translate " + inputString + " to " + outputLevel + " using options " + JSON.stringify(options));

        if (!this.tdtData.scheme.hasOwnProperty(scheme)) {
            console.error("Un-supported EPC scheme " + scheme);
            return;
        }

        if (TDTtranslator.regexHexadecimal.test(inputString) && !TDTtranslator.regexBinaryString.test(inputString)) inputString = this.hex2bin(inputString);

        let optionKey = this.tdtData.scheme[scheme][TDTtranslator.tdtDataContainer].scheme.optionKey;

        if (outputLevel == 'HEX') {
            hexOut = true;
            outputLevel = 'BINARY';
        }

        console.debug("Auto-detecting input level");
        let foundMatch = false;
        for (let level of this.tdtData.scheme[scheme][TDTtranslator.tdtDataContainer].scheme.level) {
            if (level.type == outputLevel) {
                console.debug("Found the output level");
                outputLevelData = level;
            }
            console.debug("Checking against " + level.type + " prefixMatch = " + level.prefixMatch);
            if (inputString.startsWith(level.prefixMatch)) {
                console.debug("input appears to match " + level.type);
                let testString = inputString;
                let expectedSources = [];
                for (let option of level.option) {
                    if (!option.pattern) continue;
                    if (optionKey && options.hasOwnProperty(optionKey) && (options[optionKey] != option.optionKey)) {
                        console.debug("Provided option key " + options[optionKey] + " does not match " + option.optionKey);
                        continue;
                    }

                    console.debug("optionKey = " + option.optionKey + ", pattern = " + option.pattern);

                    let pattern_suffix = "";
                    let matchGroups = [];
                    let lastSeq = 0;
                    switch (level.type) {
                        case "BINARY": {
                            if (option.grammar.includes("encodedAI")) pattern_suffix = '([01]+)';
                            break;
                        }
                        case "GS1_DIGITAL_LINK": {
                            pattern_suffix = '(.*)';
                            testString = TDTtranslator.digitalLinkPreFormat(inputString, option.aiSequence);
                            break;
                        }
                        case "GS1_AI_JSON": {
                            testString = TDTtranslator.jsonPreFormat(inputString, option.aiSequence);
                            break;
                        }
                    }

                    let re = new RegExp(option.pattern + pattern_suffix);

                    if (!re.test(testString)) {
                        console.debug("Input " + inputString + " doesn't match pattern " + option.pattern);
                        continue;
                    }

                    console.debug("inputString matches the pattern for this option");
                    matchGroups = testString.match(re);
                    for (let field of option.field) {
                        console.debug("field.name = " + field.name + ", matched value = " + matchGroups[field.seq]);
                        if (field.hasOwnProperty("encoding") && (field.encoding == "dateYYMMDD")) {
                            switch (level.type) {
                                case "BINARY": {
                                    internalMap[field.name] = TDTtranslator.fromBinaryUsingDateYYMMDD(matchGroups[field.seq]).decoded;
                                    break;
                                }
                                default: {
                                    internalMap[field.name] = matchGroups[field.seq];
                                    break;
                                }
                            }
                        } else if (field.hasOwnProperty("compaction")) {
                            if (/[0-9]-bit/.test(field.compaction)) {
                                internalMap[field.name] = TDTtranslator.fromBinaryUsingTruncatedASCII(matchGroups[field.seq], parseInt(field.compaction))
                            } else {
                                throw new Error("Unknown compaction " + field.compaction);
                            }
                        } else if ((level.type == "BINARY") && (field.hasOwnProperty("decimalMinimum"))) {
                            let value = parseInt(matchGroups[field.seq], 2).toString();
                            if (field.hasOwnProperty("length")) {
                                internalMap[field.name] = TDTtranslator.prePad(value, "0", field.length);
                            } else {
                                let found = false;
                                for (let testlevel of this.tdtData.scheme[scheme][TDTtranslator.tdtDataContainer].scheme.level) {
                                    if (testlevel.type != "TAG_ENCODING") continue;
                                    for (let testoption of testlevel.option) {
                                        if (testoption.optionKey != option.optionKey) continue;
                                        for (let testfield of testoption.field) {
                                            if (testfield.name != field.name) continue;
                                            if (testfield.hasOwnProperty("padChar")) {
                                                if (testfield.padDir == "LEFT") {
                                                    value = TDTtranslator.prePad(value, testfield.padChar, testfield.length);
                                                } else {
                                                    value = TDTtranslator.postPad(value, testfield.padChar, testfield.length)
                                                }
                                            }
                                            found = true;
                                            break;
                                        }
                                        if (found) break;
                                    }
                                    if (found) break;
                                }
                                internalMap[field.name] = value;
                            }
                        } else {
                            internalMap[field.name] = matchGroups[field.seq];
                        }
                        if (field.seq > lastSeq) lastSeq = field.seq;
                        expectedSources.push(field.name);
                    }
                    internalMap["optionKey"] = option.optionKey;
                    
                    if (optionKey && optionKey !== "gs1companyprefixlength") {
                        internalMap[optionKey] = option.optionKey;
                    }

                    if (level.type === "BINARY" && matchGroups && matchGroups[lastSeq + 1] && (scheme.includes("++") || scheme.toLowerCase().includes("plusplus"))) {
                        internalMap["binaryHostname"] = matchGroups[lastSeq + 1];
                        internalMap["_trailingBits"] = matchGroups[lastSeq + 1];
                    }
 
                    switch (level.type) {
                        case "BINARY": {
                            if (!option.hasOwnProperty("encodedAI")) break;

                            let encodedAIData = matchGroups[lastSeq+1];
                            console.debug("Decoding AIs from " + encodedAIData);
                            for (let encodedAIcomponent of option.encodedAI) {
                                let tableFrow = this.tdtData.table.F[encodedAIcomponent.ai];
                                if (tableFrow) {
                                    let value = '';
                                    let decoded = TDTtranslator.fromBinaryUsingTableF(encodedAIData, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });
                                    value += decoded.characterString;
                                    encodedAIData = encodedAIData.substr(decoded.used);
                                    if (tableFrow.j) {
                                        let decoded = TDTtranslator.fromBinaryUsingTableF(encodedAIData, { "section": tableFrow.j, "fixLenChrs" : parseInt(tableFrow.k), "fixLenBits": parseInt(tableFrow.l), "encIndBits": parseInt(tableFrow.m), "lenIndBits": parseInt(tableFrow.n), "maxChars": parseInt(tableFrow.o) });
                                        value += decoded.characterString;
                                        encodedAIData = encodedAIData.substr(decoded.used);
                                    }
                                    internalMap[encodedAIcomponent.name] = value;
                                    console.debug(JSON.stringify({"ai": encodedAIcomponent.ai, "value": value}));
                                }
                            }
                            
                            internalMap["_trailingBits"] = encodedAIData;
                            break;
                        }

                        case "GS1_AI_JSON": {
                            internalMap["plusdata"] = TDTtranslator.fromJSONExtractPlusData(testString, option.aiSequence);
                            break;
                        }

                        case "GS1_DIGITAL_LINK": {
                            internalMap["plusdata"] = TDTtranslator.fromDigitalLinkExtractPlusData(matchGroups[matchGroups.length - 1]);
                            break;
                        }
                    }

                    foundMatch = true;
                    break;
                }

                if (!foundMatch) {
                    console.debug("Input doesn't match pattern for any option");
                    continue;
                }

                if (level.hasOwnProperty("rule")) {
                    console.debug("Need to process the rules of type='EXTRACT'");
                    for (const rule of level.rule) {
                        if (rule.type != "EXTRACT") {
                            continue;
                        }
                        
                        if (rule.function.includes("binaryHostname") && internalMap.hasOwnProperty("_trailingBits")) {
                            internalMap["binaryHostname"] = internalMap["_trailingBits"];
                        }
                        
                        TDTtranslator.processRule(rule, internalMap, options, expectedSources);
                    }
                }

                if (level.type === "BINARY" && internalMap.hasOwnProperty("_trailingBits")) {
                    if (scheme.includes("++") || scheme.toLowerCase().includes("plusplus")) {
                        delete internalMap["_trailingBits"];
                    } else {
                        let consumedBitsLength = 0;
                        if (internalMap.hasOwnProperty("hostname")) {
                            let tempBin = TDTtranslator.internalHostname2Binary(internalMap["hostname"]);
                            consumedBitsLength = tempBin.length;
                        }
                        let remainingAIDCdata = internalMap["_trailingBits"].substr(consumedBitsLength);
                        internalMap["plusdata"] = TDTtranslator.fromBINARYExtractPlusData(remainingAIDCdata, this.tdtData.table.F, this.tdtData.table.K);
                        delete internalMap["_trailingBits"];
                    }
                }

                if (internalMap.hasOwnProperty("hostname") && internalMap["hostname"]) {
                    let decodedDomain = internalMap["hostname"];
                    let protocolScheme = "https://";

                    if (options.hasOwnProperty("uriStem") && options.uriStem) {
                        let protoMatch = options.uriStem.match(/^(https?:\/\/)/i);
                        if (protoMatch) protocolScheme = protoMatch[1];
                    }

                    let absoluteCustomStem = protocolScheme + decodedDomain;
                    
                    internalMap["uriStem"] = absoluteCustomStem;
                    options["uriStem"] = absoluteCustomStem;
                    
                    console.debug("PRECEDENCE ENFORCED: Re-routed execution uriStem path to use custom domain: " + absoluteCustomStem);
                }
            }
        }

        if (!foundMatch) {
            throw new TDTExtractionError("Operational Fault: Input payload pattern validation mismatch structure failure.", {
                scheme: scheme,
                level: outputLevel,
                buffer: inputString,
                gcpLength: options.gs1companyprefixlength
            });
        }

        if (internalMap.hasOwnProperty("plusdata")) {
            options.dataToggle = internalMap.plusdata.length > 0 ? 1 : 0;
        } else {
            options.dataToggle = 0;
        }

        if (!outputLevelData) {
            throw new Error("Requested output level " + outputLevel + " not found");
        }

        let finalOutputArray = [];
        let outputArrayEntries = [];
        console.debug("Requested output level " + outputLevel + " found");
        if (outputLevelData.hasOwnProperty("requiredFormattingParameters")) {
            console.debug("Required formatting parameters = " + JSON.stringify(outputLevelData.requiredFormattingParameters));
            let requiredFormattingParameters = outputLevelData.requiredFormattingParameters.split(",");
            for (let param of requiredFormattingParameters) {
                if (param === "hostname" && !options.hasOwnProperty("hostname") && !internalMap.hasOwnProperty("hostname") && options.hasOwnProperty("uriStem") && options.uriStem) {
                    try {
                        let cleanStem = options.uriStem.replace(/^https?:\/\//i, '').split('/')[0];
                        if (cleanStem) {
                            internalMap["hostname"] = cleanStem;
                        }
                    } catch(e) {}
                }

                if (options.hasOwnProperty(param) || internalMap.hasOwnProperty(param)) {
                    console.debug("Specified value for " + param + " of " + (options[param] || internalMap[param]));
                } else {
                    if (param != "tagLength") {
                        throw new Error("Missing argument " + param);
                    }
                }
            }
        }

        console.debug("internalMap : " + JSON.stringify(internalMap, null, 2));

        if (!internalMap.hasOwnProperty("optionKey")) {
            if (options.hasOwnProperty("gs1companyprefixlength")) {
                internalMap.optionKey = options.gs1companyprefixlength.toString();
            } else if (internalMap.hasOwnProperty("gs1companyprefixlength")) {
                internalMap.optionKey = internalMap.gs1companyprefixlength.toString();
            } else {
                throw new Error("No output option identified");
            }
        }

        const byOptionKeyLocal = function(optionkey) {
            return function (element) {
                if (element['optionKey'] == optionkey) { return true; }
            }
        }

        let outputOption = outputLevelData.option.filter(byOptionKeyLocal(internalMap.optionKey))[0];
        
        if (!outputOption && outputLevelData.option.length > 0) {
            outputOption = outputLevelData.option[0];
        }

        if (!outputOption) {
            throw new Error("No matching output variant group structure discovered");
        }

        console.debug("outputOption = " + JSON.stringify(outputOption, null, 2)) ;

        if (outputLevelData.hasOwnProperty("rule")) {
            let outputComponents = outputOption.grammar.match(/('.*?'|[^'\s]+)(?=\s|\s*$)/g);
            console.debug("Processing FORMAT rules");
            
            if (scheme.includes("++") || scheme.toLowerCase().includes("plusplus")) {
                if (internalMap.hasOwnProperty("hostname") && internalMap["hostname"]) {
                    let extractedHost = internalMap["hostname"];
                    let protocol = "https://";
                    if (options.hasOwnProperty("uriStem") && options.uriStem) {
                        let protoMatch = options.uriStem.match(/^(https?:\/\/)/i);
                        if (protoMatch) protocol = protoMatch[1];
                    }
                    let overrideUriStem = protocol + extractedHost;
                    internalMap["uriStem"] = overrideUriStem;
                    options["uriStem"] = overrideUriStem;
                    console.debug("PRECEDENCE ALIGNED: Forced output URI Stem Base to use domain: " + overrideUriStem);
                }

                if (internalMap.hasOwnProperty("gtin") && internalMap["gtin"]) {
                    let rawGtin = internalMap["gtin"];
                    if (rawGtin.length === 14) {
                        let gcpLen = parseInt(options.gs1companyprefixlength) || 7;
                        
                        internalMap["indicatordigit"] = rawGtin.substring(0, 1);
                        internalMap["gs1companyprefix"] = rawGtin.substring(1, 1 + gcpLen);
                        internalMap["itemrefremainder"] = rawGtin.substring(1 + gcpLen, 13);
                        internalMap["itemref"] = rawGtin.substring(0, 1) + rawGtin.substring(1 + gcpLen, 13);
                        internalMap["checkdigit"] = rawGtin.substring(13, 14);
                        
                        console.debug(`PRECEDENCE SEEDING: Structured gtin fields mapped for output generation (GCP Length: ${gcpLen})`);
                    }
                }
            }
            
            for (const rule of outputLevelData.rule) {
                if (rule.type != "FORMAT") continue;
                TDTtranslator.processRule(rule, internalMap, options, outputComponents);
            }
        }

        let binaryEncodedAI = [];
        let encodedAIs = [];
        if (outputOption.hasOwnProperty("encodedAI")) {
            for (let encodedAIcomponent of outputOption.encodedAI) {
                if (!encodedAIcomponent.hasOwnProperty("ai")) continue;

                let tableFrow = this.tdtData.table.F[encodedAIcomponent.ai];
                if (tableFrow) {
                    console.debug("TableF row for AI (" + encodedAIcomponent.ai + "): " + JSON.stringify(tableFrow, null, 2));

                    let aiValue = internalMap[encodedAIcomponent.name];
                    let encodedAIDataOutput = [];

                    let componentCount = 1;
                    console.debug("Using method " + tableFrow.b + " for encoding component " + componentCount + " as defined in TDS section " + tableFrow.c);

                    let componentValue = aiValue;
                    if (tableFrow.j) {
                        componentValue = componentValue.substr(0, tableFrow.d)
                    }
                    let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });
                    encodedAIDataOutput.push(b.binary);

                    if (tableFrow.j) {
                        componentCount ++;
                        componentValue = aiValue.substr(tableFrow.d);
                        console.debug("Using method " + tableFrow.i + " for encoding component " + componentCount + " as defined in TDS section " + tableFrow.j);
                        let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.j, "fixLenChrs" : parseInt(tableFrow.k), "fixLenBits": parseInt(tableFrow.l), "encIndBits": parseInt(tableFrow.m), "lenIndBits": parseInt(tableFrow.n), "maxChars": parseInt(tableFrow.o) });
                        encodedAIDataOutput.push(b.binary);
                    }

                    binaryEncodedAI.push(encodedAIDataOutput.join(""));
                    encodedAIs.push(encodedAIcomponent.ai);
                }
            }
            console.debug("binaryEncodedAI = " + JSON.stringify(binaryEncodedAI));
        }

        for (let grammarComponent of outputOption.grammar.match(/('.*?'|[^'\s]+)(?=\s|\s*$)/g)) {
            console.debug("grammarComponent = " + grammarComponent);
            if (/^'(.+?)'$/.test(grammarComponent)) {
                console.debug(grammarComponent + " is literal");
                finalOutputArray.push(grammarComponent.replace(/^'/,"").replace(/'$/,""));
                outputArrayEntries.push('literal')
            }
            if (/^[a-zA-Z][a-zA-Z0-9_]*$/.test(grammarComponent)) {
                console.debug("Non-literal grammar component : " + grammarComponent);

                switch (grammarComponent) {
                    case "dataToggle": {
                        console.debug("Append the dataToggle value of " + options['dataToggle']);
                        if (/^[01]$/.test(options['dataToggle'])) {
                            finalOutputArray.push(options['dataToggle'].toString());
                            outputArrayEntries.push('dataToggle');
                        } else {
                            console.error(options['dataToggle'] + " must be 0 or 1");
                        }
                        continue;
                    }

                    case "filter": {
                        let filter = options["filter"];
                        if (internalMap.hasOwnProperty("filter")) {
                            filter = internalMap["filter"]
                        }
                        console.debug("Append the filter value of " + filter);
                        if (outputLevel == "BINARY") {
                            let bitLength = 3;
                            for (let field of outputOption.field) {
                                if (field.name == 'filter') {
                                    bitLength = field.bitLength;
                                }
                            }
                            finalOutputArray.push(TDTtranslator.prePad(parseInt(filter).toString(2), "0", bitLength));
                        } else {
                            finalOutputArray.push(filter);
                        }
                        outputArrayEntries.push('filter');
                        continue;
                    }

                    case "encodedAI": {
                        console.debug("Append the concatenation of binaryEncodedAI " + JSON.stringify(binaryEncodedAI));
                        let aiIndex = 0;
                        for (let el of binaryEncodedAI) {
                            finalOutputArray.push(el);
                            outputArrayEntries.push('AI ' + encodedAIs[aiIndex] + ' data');
                            aiIndex++;
                        }
                        continue;
                    }

                    default: {
                        if (options.hasOwnProperty(grammarComponent)) {
                            console.debug("Match found in options for " + grammarComponent);
                            finalOutputArray.push(options[grammarComponent]);
                            outputArrayEntries.push(grammarComponent);
                            continue
                        }

                        if (outputOption.hasOwnProperty("field")) {
                            let found = false;
                            for (let f of outputOption.field) {
                                if ((f.name == grammarComponent) && (internalMap.hasOwnProperty(f.name))) {
                                    console.debug("Match found for field " + JSON.stringify(f));
                                    if (f.hasOwnProperty("encoding") && (f.encoding == "dateYYMMDD")) {
                                        switch (outputLevel) {
                                            case "BINARY": {
                                                finalOutputArray.push(TDTtranslator.toBinaryUsingDateYYMMDD(internalMap[f.name]));
                                                break;
                                            }
                                            default: {
                                                finalOutputArray.push(internalMap[f.name]);
                                                break;
                                            }
                                        }
                                    } else if (f.hasOwnProperty("compaction")) {
                                        switch (outputLevel) {
                                            case "BINARY": {
                                                if (/[0-9]-bit/.test(f.compaction)) {
                                                    let binary = TDTtranslator.toBinaryUsingTruncatedASCII(internalMap[f.name], parseInt(f.compaction));
                                                    if (f.hasOwnProperty("bitLength")) {
                                                        if (f.bitPadDir == "LEFT") {
                                                            binary = TDTtranslator.prePad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                        } else {
                                                            binary = TDTtranslator.postPad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                        }
                                                    }
                                                    finalOutputArray.push(binary);
                                                } else {
                                                    throw new Error("Unknown compaction " + field.compaction);
                                                }
                                                break;
                                            }
                                            default: {
                                                finalOutputArray.push(internalMap[f.name])
                                                break;
                                            }
                                        }
                                    } else if (f.hasOwnProperty("decimalMinimum")) {
                                        switch (outputLevel) {
                                            case "BINARY": {
                                                let binary = parseInt(internalMap[f.name]).toString(2);
                                                if (binary == "NaN") binary = '';
                                                if (f.hasOwnProperty("bitLength")) {
                                                    if (f.bitPadDir == "LEFT") {
                                                        binary = TDTtranslator.prePad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                    } else {
                                                        binary = TDTtranslator.postPad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                    }
                                                }
                                                finalOutputArray.push(binary)
                                                break;
                                            }
                                            default: {
                                                let value = internalMap[f.name];
                                                if (f.hasOwnProperty("length")) {
                                                    if (f.padDir == "LEFT") {
                                                        value = TDTtranslator.prePad(value, f.padChar, f.length);
                                                    } else {
                                                        value = TDTtranslator.postPad(value, f.padChar, f.length);
                                                    }
                                                }
                                                finalOutputArray.push(value);
                                                break;
                                            }
                                        }
                                    } else {
                                        finalOutputArray.push(internalMap[f.name]);
                                    }
                                    outputArrayEntries.push(f.name);
                                    found = true;
                                    break;
                                }
                            }
                            if (found) continue;
                        }

                        if (internalMap.hasOwnProperty(grammarComponent)) {
                            console.debug("Match found in internal map");
                            finalOutputArray.push(internalMap[grammarComponent]);
                            outputArrayEntries.push(grammarComponent);
                            continue;
                        }
                    }
                }
            }
        }

        if (internalMap.hasOwnProperty("plusdata") && (internalMap.plusdata.length > 0)) {
            switch(outputLevel) {
                case "BINARY": {
                    if (outputOption.grammar.includes("dataToggle")) {
                        let [plusdata, plusdataComps] = TDTtranslator.toBINARYEncodePlusData(internalMap.plusdata, this.tdtData.table.F, true)
                        for (let d of plusdata) finalOutputArray.push(d);
                        for (let d of plusdataComps) outputArrayEntries.push(d);
                    }
                    break;
                }
                case "GS1_AI_JSON": {
                    finalOutputArray[finalOutputArray.length - 1] = '"';
                    finalOutputArray.push(TDTtranslator.toJSONEncodePlusData(internalMap.plusdata));
                    outputArrayEntries.push('AIDC+');
                    finalOutputArray.push("}");
                    outputArrayEntries.push('literal');
                    break;
                }
                case "GS1_DIGITAL_LINK": {
                    if (outputOption.grammar.includes('?')) {
                        finalOutputArray.push("&");
                    } else {
                        finalOutputArray.push("?");
                    }
                    outputArrayEntries.push('literal');
                    finalOutputArray.push(TDTtranslator.toDigitalLinkEncodePlusData(internalMap.plusdata));
                    outputArrayEntries.push('AIDC+');
                    break;
                }
            }
        }

        console.debug("finalOutputArray = " + JSON.stringify(finalOutputArray));
        let returnString = finalOutputArray.join("");

        if ((outputLevel == "GS1_DIGITAL_LINK") && (outputLevelData.gs1DigitalLinkKeyQualifiers.length > 0)) {
            returnString = TDTtranslator.digitalLinkPostFormat(returnString, outputLevelData.gs1DigitalLinkKeyQualifiers);
        }

        if (hexOut) returnString = this.bin2hex(returnString);

        console.debug("output string = " + returnString);
        if (options.hasOwnProperty('returnArray') && (options['returnArray'])) {
            return [finalOutputArray, outputArrayEntries];
        } else {
            return returnString;
        }
    }

    schemes() {
        if (this.tdtData && this.tdtData.scheme) {
            return Object.keys(this.tdtData.scheme);
        } else {
            return [];
        }
    }

    bin2hex(inputBinaryString) {
        let outputHexString = "";

        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only 0 or 1 allowed: " + inputBinaryString);
        }

        for (let t = 0; t < inputBinaryString.length; t += 4) {
            let binary = inputBinaryString.substr(t, 4);
            binary = TDTtranslator.postPad(binary, "0", 4);
            outputHexString += parseInt(binary, 2).toString(16).toUpperCase();
        }
        return outputHexString;
    }

    hex2bin(inputHexString) {
        let outputBinaryString = "";

        if (!TDTtranslator.regexHexadecimal.test(inputHexString)) {
            throw new Error("Input is not hexadecimal - only 0-9A-F allowed");
        }

        for (let t = 0; t < inputHexString.length; t++) {
            outputBinaryString += TDTtranslator.prePad(parseInt(inputHexString.charAt(t), 16).toString(2), "0", 4);
        }
        return outputBinaryString;
    }

    static #byFile(filename) {
        return function (element) {
            if (element['file'] == filename) { return true; }
        }
    }

    static #unwrapDataByFilename(data, key) {
        return data.filter(TDTtranslator.#byFile(key))[0].data;
    }

}

// Map globally exposed utility components back to the constructor interface flawlessly
TDTtranslator.prePad = TDTtranslator.prePad;
TDTtranslator.toBinaryUsingTableF = TDTtranslator.toBinaryUsingTableF;
TDTtranslator.fromBinaryUsingTableF = TDTtranslator.fromBinaryUsingTableF;