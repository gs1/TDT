/**
 * ============================================================================
 * GS1 Tag Data Translation (TDT) Engine
 * Version 2.3 (draft)
 * ============================================================================
 * * @license Apache-2.0
 * @see {@link https://raw.githubusercontent.com/gs1/TDT/refs/heads/main/DISCLAIMER.md|GS1 TDT Disclaimer and Limitations of Liability}
 * * @author Nick Porter <nick@portercomputing.co.uk>
 * @author Mark Harrison <mark.harrison@gs1.org>
 * * * OVERVIEW FOR JUNIOR DEVELOPERS:
 * This engine handles bi-directional conversion between various representations
 * of GS1 identification keys (e.g., GTIN, SSCC, GRAI) across different data layers:
 * 1. Pure Identity URI (e.g., urn:epc:id:sgtin:...)
 * 2. Tag Encoding URI (e.g., urn:epc:tag:sgtin-96:...)
 * 3. Binary / Hex bitstreams (used in physical RFID tags or barcodes)
 * 4. GS1 AI element strings / GS1 Digital Links (JSON, URL syntax)
 * * CORE ARCHITECTURAL FLOW:
 * - INITIALIZATION: Loads structural schemas (manifests, optimization tables, prefix format lists)
 * asynchronously from a ZIP archive and JSON endpoints.
 * - AUTO-DETECTION: Analyzes incoming syntax formats using pre-cached regular expressions to identify 
 * the EPC scheme and source level automatically.
 * - TRANSLATION LOOP: Parses inputs via declarative regex matching patterns, normalizes the extracted 
 * tokens via custom macro function rules, converts them via high-density bit compaction codecs, 
 * and sequences them cleanly into the requested output structural grammar.
 */
 
/**
 * Recursively locks down objects and arrays to prevent unauthorized runtime mutation.
 * This guarantees the operational integrity of loaded configuration maps across execution threads.
 * * @param {Object|Array} object - Target data structure context to freeze.
 * @returns {Object|Array} The identical immutable frozen data reference context.
 */
function deepFreeze(object) {
    if (object && typeof object === "object") {
        // Retrieve all primitive properties belonging directly to the object context
        const propNames = Object.getOwnPropertyNames(object);
        for (const name of propNames) {
            const value = object[name];
            // If a nested property is an array or object, freeze it recursively
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

/**
 * Custom Error class designed to capture detailed internal state diagnostics 
 * when structural translation paths or syntax boundaries fail validation constraints.
 * * @class TDTExtractionError
 * @extends {Error}
 */
class TDTExtractionError extends Error {
    /**
     * Constructs an enriched error instance providing a transparent window into 
     * structural validation faults for engineers unfamiliar with GS1 syntax boundaries.
     * * @param {string} message - Human-readable diagnostic description of the validation failure.
     * @param {Object} [context={}] - Snapshot parameters of the runtime compilation path.
     * @param {string} [context.scheme=null] - The target EPC scheme being processed (e.g., 'sgtin').
     * @param {string} [context.level=null] - The target output processing level where extraction failed.
     * @param {string} [context.buffer=null] - A copy of the raw text or bitstream buffer during processing.
     * @param {number} [context.gcpLength=null] - The evaluated GS1 Company Prefix length used during parsing.
     */
    constructor(message, context = {}) {
        super(message);
        this.name = "TDTExtractionError";
        this.scheme = context.scheme || null;
        this.failedLevel = context.level || null;
        this.inputBufferSnapshot = context.buffer || null;
        this.gcpLengthEvaluated = context.gcpLength || null;
        
        // Ensure V8 engines properly preserve the original stack trace trace line references
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, TDTExtractionError);
        }
    }
}

// ----------------------------------------------------------------------------
// APPLICATION ENGINE LAYER: BI-DIRECTIONAL TRANSLATION ENGINE
// ----------------------------------------------------------------------------

/**
 * Main application interface processing declarative rules and encoding schemes 
 * compliant with the GS1 Tag Data Standard (TDS).
 * * @class TDTtranslator
 */
class TDTtranslator {

    // V8 Engine Optimization: Private Static Regex Map Cache
    // Pre-compiling expressions prevents expensive re-allocation within loops.
    static regexBinaryString = /^[01]+$/;
    static regexURNcode40 = /^[A-Z0-9\.:-]+$/;
    static regexFileSafeURISafeBase64 = /^[A-Za-z0-9_-]+$/;
    static regexUpperCaseHexadecimal = /^[0-9A-F]+$/;
    static regexLowerCaseHexadecimal = /^[0-9a-f]+$/;
    static regexHexadecimal = /^[0-9A-Fa-f]+$/;
    static regexAlphanumeric = /^[\x21-\x23\x25-\x5A\x5F\x61-\x7A]+$/;
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

    // Static Character Alphabets Map (Used directly by compaction codecs)
    static alphabetURNcode40 = " ABCDEFGHIJKLMNOPQRSTUVWXYZ-.:0123456789";
    static alphabetFileSafeURISafeBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static alphabetUpperCaseHexadecimal = "0123456789ABCDEF";
    static alphabetLowerCaseHexadecimal = "0123456789abcdef";
    static fromAItoPrioritisedDateIndicator = {"11":"0000","13":"0001","15":"0010","16":"0011","17":"0100","7006":"0101","7007":"0110"};

    // Encapsulated Substring Allocation Mapping Optimization Cache Tables
    // Populated dynamically at startup via #fetchAllData() from JSON files.
    static optimisation7bitTableA = [];
    static optimisation14bitTableB1 = [];
    static optimisation14bitTableB2 = [];
    static optimisation14bitTableB3 = [];
    static optimisation14bitTableB4 = [];

    /**
     * Initializes a new instance of the TDTtranslator engine context.
     * Sets up empty instance-level caches and explicitly establishes method bindings.
     * Launches external operational asset fetching immediately upon instantiation.
     */
    constructor() {
        /**
         * Core lookup store mapping schemes and rule tables parsed from metadata assets.
         * @type {Object}
         */
        this.tdtData = {};
        
        /**
         * Key-value registry cache holding global GS1 Company Prefix length assignment rules.
         * @type {Object}
         */
        this.gcpLengths = {};

        // Explicit Instance Self-Binding Policy:
        // Guarantees stable lexical scope references when handler methods are passed as callbacks.
        this.translate = this.translate.bind(this);
        this.autodetect = this.autodetect.bind(this);

        /**
         * Promise representing the asynchronous lifecycle completion of configuration loading.
         * @type {Promise<TDTtranslator>}
         */
        this.initialized = this.#fetchAllData(); 
    }

    /**
     * Co-ordinates the parallel retrieval and parsing of core schema zip containers 
     * and external prefix structural specification definitions.
     * * @private
     * @returns {Promise<TDTtranslator>} Resolves with the instance reference upon successful configuration parsing.
     */
    #fetchAllData() {
        return this.#fetchDirectoryData('./schemas/')
            .catch(() => this.#fetchDirectoryData('./2026-09-15a_TDT_2-3_artefacts/'))
            .catch(() => this.#fetchZipData('./TDT_JSON_artefacts.zip'))
            .then((loadedData) => {
                // Extract master document routing list outlining expected table parameters
                let manifestData = TDTtranslator.#unwrapDataByFilename(loadedData, "manifest.json");

                this.tdtData.table = {};
                this.tdtData.scheme = {};

                // Route table array entries directly into static parsing optimizations or lookup fields
                for (let tableEntry of manifestData.tables) {
                    console.debug(JSON.stringify(tableEntry));
                    let rawData = TDTtranslator.#unwrapDataByFilename(loadedData, tableEntry.file);
                    
                    if (tableEntry.table === "Opt_A" || tableEntry.table === "A") {
                        TDTtranslator.optimisation7bitTableA = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B1" || tableEntry.table === "B1") {
                        TDTtranslator.optimisation14bitTableB1 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B2" || tableEntry.table === "B2") {
                        TDTtranslator.optimisation14bitTableB2 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B3" || tableEntry.table === "B3") {
                        TDTtranslator.optimisation14bitTableB3 = TDTtranslator.normalizeGS1Table(rawData);
                    } else if (tableEntry.table === "Opt_B4" || tableEntry.table === "B4") {
                        TDTtranslator.optimisation14bitTableB4 = TDTtranslator.normalizeGS1Table(rawData);
                    } else {
                        let rows = {};
                        for (let row of rawData.rows) {
                            rows[row.a] = row; // Map systematically by internal row descriptor key
                        }
                        this.tdtData.table[tableEntry.table] = Object.freeze(rows);
                    }
                }

                // Protect optimization cache surfaces from internal state leaks or accidental runtime pollution
                deepFreeze(TDTtranslator.optimisation7bitTableA);
                deepFreeze(TDTtranslator.optimisation14bitTableB1);
                deepFreeze(TDTtranslator.optimisation14bitTableB2);
                deepFreeze(TDTtranslator.optimisation14bitTableB3);
                deepFreeze(TDTtranslator.optimisation14bitTableB4);

                // Populate declarative tracking structures for each discrete key format (e.g., sgtin, sscc)
                for (let scheme of manifestData.definitionFiles) {
                    console.debug(JSON.stringify(scheme));
                    this.tdtData.scheme[scheme.scheme] = deepFreeze(TDTtranslator.#unwrapDataByFilename(loadedData, scheme.file));
                }
                return this;
            })
            .catch(error => {
                console.error('Error fetching structural verification sources:', error);
                throw error;
            });
    }

    /**
     * Fetches unzipped JSON schema and table files directly from a directory.
     * @private
     * @param {string} baseDir - Target relative directory containing manifest.json and table files.
     * @returns {Promise<Array<Object>>} Collection array housing individual parsed file properties.
     */
    #fetchDirectoryData(baseDir) {
        if (typeof process !== 'undefined' && process.versions && process.versions.node && typeof require === 'function') {
            try {
                const fs = require('fs');
                const path = require('path');
                const resolvedDir = path.resolve(process.cwd(), baseDir);
                if (fs.existsSync(resolvedDir)) {
                    const manifestPath = path.join(resolvedDir, 'manifest.json');
                    if (fs.existsSync(manifestPath)) {
                        const manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
                        const results = [{ id: 'manifest', file: 'manifest.json', data: manifestData }];
                        if (manifestData.tables) {
                            for (const tableEntry of manifestData.tables) {
                                const filePath = path.join(resolvedDir, tableEntry.file);
                                if (fs.existsSync(filePath)) {
                                    results.push({
                                        id: tableEntry.file.replace(/\.json$/, ''),
                                        file: tableEntry.file,
                                        data: JSON.parse(fs.readFileSync(filePath, 'utf8'))
                                    });
                                }
                            }
                        }
                        if (manifestData.definitionFiles) {
                            for (const scheme of manifestData.definitionFiles) {
                                const filePath = path.join(resolvedDir, scheme.file);
                                if (fs.existsSync(filePath)) {
                                    results.push({
                                        id: scheme.file.replace(/\.json$/, ''),
                                        file: scheme.file,
                                        data: JSON.parse(fs.readFileSync(filePath, 'utf8'))
                                    });
                                }
                            }
                        }
                        return Promise.resolve(results);
                    }
                }
            } catch (err) {
                // fall through to fetch
            }
        }

        const resolveUrl = (u) => (typeof window !== 'undefined' && window.location ? new URL(u, window.location.href).href : u);

        return fetch(resolveUrl(baseDir + 'manifest.json'))
            .then(response => {
                if (!response.ok) throw new Error(`Failed to fetch manifest from ${baseDir}`);
                return response.json();
            })
            .then(manifestData => {
                const results = [{ id: 'manifest', file: 'manifest.json', data: manifestData }];
                const promises = [];

                if (manifestData.tables) {
                    for (const tableEntry of manifestData.tables) {
                        promises.push(
                            fetch(resolveUrl(baseDir + tableEntry.file))
                                .then(r => {
                                    if (!r.ok) throw new Error(`Failed to fetch ${tableEntry.file} from ${baseDir}`);
                                    return r.json();
                                })
                                .then(data => ({
                                    id: tableEntry.file.replace(/\.json$/, ''),
                                    file: tableEntry.file,
                                    data: data
                                }))
                        );
                    }
                }

                if (manifestData.definitionFiles) {
                    for (const scheme of manifestData.definitionFiles) {
                        promises.push(
                            fetch(resolveUrl(baseDir + scheme.file))
                                .then(r => {
                                    if (!r.ok) throw new Error(`Failed to fetch ${scheme.file} from ${baseDir}`);
                                    return r.json();
                                })
                                .then(data => ({
                                    id: scheme.file.replace(/\.json$/, ''),
                                    file: scheme.file,
                                    data: data
                                }))
                        );
                    }
                }

                return Promise.all(promises).then(loadedFiles => results.concat(loadedFiles));
            });
    }
    
    /**
     * Communicates with external URI locations to extract binary data, unpack it 
     * using JSZip, and read JSON configuration profiles asynchronously.
     * * @private
     * @param {string} url - Target asset path such as 'TDT_JSON_artefacts.zip'.
     * @returns {Promise<Array<Object>>} Collection array housing individual parsed file properties.
     */
    #fetchZipData(url) {
        const resolveUrl = (u) => (typeof window !== 'undefined' && window.location ? new URL(u, window.location.href).href : u);
        return fetch(resolveUrl(url))
            .then(response => {
                if (!response.ok) throw new Error(`Failed to fetch zip package data from ${url}`);
                return response.blob();
            })
            .then(blob => JSZip.loadAsync(blob))
            .then(function (zip) {
                const promises = [];
                // Enumerate systematically through unpacked entries in the directory structure
                zip.forEach((relativePath, zipEntry) => {
                    // Filter down to process only genuine native JSON records while omitting metadata paths
                    if (!(relativePath.startsWith('__MACOS')) && (relativePath.endsWith('.json'))) {
                        let localPart = relativePath.replace(/^.+?\//, "");
                        let relativePathWithoutSuffix = localPart.replace(/\.json$/, "");
                        console.debug('Parsing ' + relativePath);
                        
                        // Push extraction promise tracking payload objects into container fields
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

    /**
     * Diagnostics capability utility printing state parameters detailing schema 
     * availability limits directly to standard runtime console channels.
     * * @returns {void}
     */
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
    
    /**
     * Harmonizes variations in column naming schemas within internal GS1 schema files 
     * to build standardized flat arrays containing consistent token-mapping attributes.
     * * @static
     * @param {Object} rawJSON - Unprocessed content of any of TDT optimisation tables A, B1-B4.
     * @returns {Array<Object>} Normalized map structure arrays with standardized binary and substring properties.
     */
    static normalizeGS1Table(rawJSON) {
        if (!rawJSON || !rawJSON.rows) return [];
        const columns = rawJSON.columns || [];
    
        const binaryKey = columns.find(c => c.name === "binary" || c.title === "binary")?.id || "a";
        const substringKey = columns.find(c => c.name === "substring" || c.title === "substring")?.id || "b";
        return rawJSON.rows
            .filter(row => !row.d && (row[substringKey] !== undefined || row.c !== undefined))
            .map(row => {
                const bin = String(row[binaryKey]).trim();
                const sub = String(row.c !== undefined ? row.c : row[substringKey]).trim();
                return {
                    "binary": bin,
                    "substring": sub,
                    "bitLength": bin.length
                };
            });
    }

    /**
     * Swaps keys and values within a basic associative map context to enable reverse lookup paths.
     * * @static
     * @param {Object} obj - Source dictionary object reference context.
     * @returns {Object} A new inverted dictionary object context.
     */
    static reverseHash(obj) {
        let reversed = {};
        let keys = Object.keys(obj);
        for (let i = 0; i < keys.length; i++) {
            reversed[obj[keys[i]]] = keys[i];
        }
        return reversed;
    }

    /**
     * Dynamic property getter generating a reverse lookup directory map 
     * translating Prioritised Date indicators back to their respective GS1 AI keys.
     * * @static
     * @type {Object} Inverted dictionary key framework map context.
     */
    static get fromPrioritisedDateIndicatorToAI() {
        return TDTtranslator.reverseHash(TDTtranslator.fromAItoPrioritisedDateIndicator);
    }

    /**
     * Executes standard GS1 Luhn-style modulo 10 checksum logic to compute check digits.
     * Alternates multipliers of 3 and 1 to validate numerical integrity boundaries.
     * * @static
     * @param {string} gs1IDValue - Pure numeric evaluation string.
     * @throws {Error} If character sequence boundaries contain non-numeric data elements.
     * @returns {number} Resulting GS1 check digit integer value in the range 0 to 9.
     */
    static calculateGS1CheckDigit(gs1IDValue) {
        if (TDTtranslator.regexAllNumeric.test(gs1IDValue)) {
            let counter = 0;
            let total = 0;
            // Iterate backwards through the numerical string profile
            for (let i = gs1IDValue.length - 1; i >= 0; i--) {
                total += ((gs1IDValue.charAt(i)) * (3 - 2 * (counter % 2)));
                counter++;
            }
            return (10 - (total % 10)) % 10;
        } else {
            throw new Error("Cannot calculate a GS1 Check Digit for " + gs1IDValue + " because it is not a numeric string of digits 0-9 only");
        }
    }

    /**
     * High-order helper function generating a closure predicate to match internal binary encoding types.
     * * @static
     * @param {string} indicator - Selected encoding indicator value.
     * @returns {Function} Predicate evaluation module used in Array filter pipelines.
     */
    static matchEncodingIndicator(indicator) {
        return function(element) {
            return element.indicator == indicator;
        }
    }

    /**
     * Encodes a string hostname into its optimal binary representation.
     * Compares two strategies to find the smallest bit footprint:
     * - Strategy A: URN Code 40 Polynomial base-40 compaction packing.
     * - Strategy B: Optimized Huffman-Substring matching using 7-bit ASCII tables.
     * * @static
     * @param {string} hostname - Domain tracking label string context.
     * @throws {Error} If empty input is provided or if syntax violations occur against permitted character groups.
     * @returns {string} Fully packaged binary bit stream detailing structural parameters.
     */
    static internalHostname2Binary(hostname) {
        if (!hostname) throw new Error("Empty Hostname provided");
        if (!TDTtranslator.regexPermittedHostname.test(hostname)) {
            throw new Error("Validation Error: Hostname contains characters forbidden by standard GS1 TDT schemas.");
        }

        // Shared micro helpers supporting structure building steps
        const localPrePad = (str, padChar, len) => str.length < len ? padChar.repeat(len - str.length) + str : str;
        const buildLengthIndicator = (l) => localPrePad(l.toString(2), "0", 6);

        // --------------------------------------------------------------
        // Strategy A: URN Code 40 Polynomial Packing Method
        // --------------------------------------------------------------
        let urnResult = null;
        if (TDTtranslator.regexURNcode40.test(hostname)) {
            let workStr = hostname;
            // Ensure inputs split evenly into clusters of 3 characters by padding space indices
            if (workStr.length % 3 > 0) {
                workStr += " ".repeat(3 - (workStr.length % 3));
            }
            let binaryPayload = "";
            for (let t = 0; t < workStr.length / 3; t++) {
                const i1 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t));
                const i2 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 1));
                const i3 = TDTtranslator.alphabetURNcode40.indexOf(workStr.charAt(3 * t + 2));
                // Base-40 formula transformation matching explicit standard specifications
                const b = localPrePad(((1600 * i1 + 40 * i2 + i3 + 1) >>> 0).toString(2), "0", 16);
                binaryPayload += b;
            }
            urnResult = {
                indicator: "0", // Strategy marker bit
                lengthBin: buildLengthIndicator(hostname.length),
                payload: binaryPayload,
                totalBits: 1 + 6 + binaryPayload.length
            };
        }

        // --------------------------------------------------------------
        // Strategy B: Optimized Huffman-Substring 7-bit ASCII Tokenized Matcher
        // --------------------------------------------------------------
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
            
            // Collect matching target lookups tracking across optimizing structures
            for (let table of tables) {
                for (let el of table) {
                    if (hostname.indexOf(el.substring) > -1) optimisations.push(el);
                }
            }
            
            // Prioritize longer tokens first; for equal length, prioritize fewer bits (7-bit over 14-bit)
            optimisations.sort((a, b) => {
                if (b.substring.length !== a.substring.length) {
                    return b.substring.length - a.substring.length;
                }
                return (a.bitLength || a.binary.length) - (b.bitLength || b.binary.length);
            });
            
            // Isolate non-overlapping compression tokens systematically
            let finalOptimisations = [];
            let optimisationsRemoved = hostname;
            for (let el of optimisations) {
                let p = optimisationsRemoved.indexOf(el.substring);
                if (p > -1) {
                    finalOptimisations.push(el);
                    optimisationsRemoved = optimisationsRemoved.replace(el.substring, "");
                }
            }
            
            // Build linear token maps across character sequence intervals
            let tokens = [];
            let cursor = 0;
            let sb = [];
            while (cursor < hostname.length) {
                let foundOptimisation = false;
                for (let o of finalOptimisations) {
                    if (hostname.startsWith(o.substring, cursor)) {
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

            // Compile bits via fallback mechanisms or dictionary items
            let finalBinaryBuffer = [];
            for (let t of tokens) {
                if (typeof t === "string") {
                    for (let i = 0; i < t.length; i++) {
                        const charCode = t.charCodeAt(i);
                        if (charCode > 127) throw new Error("Non-ASCII character");
                        finalBinaryBuffer.push(charCode.toString(2).padStart(8, "0").substr(1)); // 7-bit format slice
                    }
                } else {
                    finalBinaryBuffer.push(t.binary);
                }
            }
            let asciiPayload = finalBinaryBuffer.join("");
            let virtualLength = asciiPayload.length / 7;
            asciiResult = {
                indicator: "1", // Strategy marker bit
                lengthBin: buildLengthIndicator(virtualLength),
                payload: asciiPayload,
                totalBits: 1 + 6 + asciiPayload.length
            };
        } catch (err) {}

        // Select the format with the shortest output bit length
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

    /**
     * Decodes an isolated binary segment back into a readable alphanumeric domain string 
     * by reversing either polynomial base-40 packing or tokenized ASCII compression.
     * * @static
     * @param {string} fullBitString - Isolated block sequence containing binary details.
     * @throws {Error} On formatting size mismatches, syntax faults, or invalid layout rules.
     * @returns {string} Unpacked character string representing domain identifiers.
     */
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

        // Decode Strategy A: URN Code 40
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
                // Invert the base-40 calculation formula
                const c3 = (n - 1) % 40;
                const c2 = (((n - 1) - c3) / 40) % 40;
                const c1 = (n - 1 - c3 - 40 * c2) / 1600;
                outputCharacterString += TDTtranslator.alphabetURNcode40.charAt(c1) + TDTtranslator.alphabetURNcode40.charAt(c2) + TDTtranslator.alphabetURNcode40.charAt(c3);
            }
            return outputCharacterString.substring(0, lengthIndicatorVal);
        }

        // Decode Strategy B: Huffman-Substring ASCII Compaction
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
                
                // Scan the optimization tables sequentially to decode chunks back into tokens
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
                // Fallback to plain 7-bit character translation if no table optimization matched
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
    
    /**
     * Executes declarative macro functions outlined inside standard XML/JSON TDT schema 
     * instructions to alter data tokens or populate output structure maps dynamically.
     * * @static
     * @param {Object} rule - Declarative instruction detailing functional processing rules.
     * @param {string} rule.newFieldName - Destination property key key within target storage context maps.
     * @param {string} rule.function - Function signature metadata syntax string (e.g., 'CONCAT(A,B)').
     * @param {string} rule.type - Execution lifecycle bucket category flag ('EXTRACT' or 'FORMAT').
     * @param {Object} internalMap - Context dictionary storing extracted working tokens.
     * @param {Object} options - User configuration overrides passed to the core engine thread.
     * @param {Array<string>} checkList - Context parameters required by the active execution grammar loop.
     * @throws {Error} On missing parameters or failing validation rules during macro processing.
     * @returns {void} Updates the shared state dictionary parameters in-place.
     */
    static processRule(rule, internalMap, options, checkList) {
        console.debug("Processing rule " + JSON.stringify(rule, null, 2));

        // Skip rule execution if target property parameter is already populated
        if (internalMap.hasOwnProperty(rule.newFieldName)) return;

        let func = TDTtranslator.regexRule.exec(rule.function);
        func.shift(); // Remove default match element array index bounds
        if (func.length < 2) {
            throw new Error("Failed parsing rule");
        }
        let args = func[1].split(",");

        // Standardize arguments by converting references into raw variable parameters
        let argVals = [];
        for (let a of args) {
            if (TDTtranslator.regexAllNumeric.test(a)) {
                argVals.push(a);
                continue;
            }

            if (a.match(TDTtranslator.regexStatic)) {
                console.debug(a + " is a static value");
                let vals = TDTtranslator.regexStatic.exec(a);
                argVals.push(vals[1]); // Extract literal character sequence definitions directly
                continue;
            }

            console.debug("Looking for " + a);
            if (!internalMap.hasOwnProperty(a)) {
                // Safeguard against missing input values depending on the phase type boundary parameters
                if (rule.type == "EXTRACT" && !checkList.includes(a) && !options.hasOwnProperty(a)) {
                    console.debug(a + " not in input - skipping rule");
                    return;
                }
                if (rule.type == "FORMAT" && !checkList.includes(rule.newFieldName)) {
                    console.debug(rule.newFieldName + " not required - skipping rule");
                    return;
                }				
                
                // Fallback mechanism to parse out a hostname if a URI stem exists
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

        // Router routing across identified macro capability commands
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

    /**
     * Enforces explicit ordering of properties in a JSON string block based on an 
     * application identifier sequence list. This ensures structural predictability.
     * * @static
     * @param {string} string - Raw incoming input data payload layout text block string.
     * @param {Array<string>} aiSequence - Ordered listing outlining parsing parameters to isolate first.
     * @returns {string} Re-ordered structured JSON block text contents, or empty string on validation failure.
     */
    static jsonPreFormat(string, aiSequence) {
        let parsed = JSON.parse(string);
        let formatted = '{';

        // Process expected primary attributes first
        for (let ai of aiSequence) {
            if (ai in parsed) {
                formatted += '"' + ai + '":"' + parsed[ai] + '",';
                delete parsed[ai]; // Remove processed fields to isolate remaining fields
            } else {
                return "";
            }
        }

        // Append any remaining non-sequence attributes
        for (let ai in parsed) {
            formatted += '"' + ai + '":"' + parsed[ai] + '",';
        }
        formatted = formatted.slice(0, -1) + "}";
        console.debug("Pre-formatted JSON " + formatted)
        return formatted;
    }

    /**
     * Extracts and shifts key identifiers from raw Web URI path strings into structured 
     * sequence configurations matching strict positional grammar rules.
     * * @static
     * @param {string} string - Raw incoming digital link URI sequence input context data text.
     * @param {Array<string>} aiSequence - Ordered key parameters requiring structural compliance prioritization.
     * @returns {string} Normalized layout block URL representation properties, or empty text.
     */
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
        // Parse the URL path string segments systematically
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

        // Parse trailing query parameter attributes
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

        // Append isolated trailing extension properties back onto output structures
        for (let ai in extra) {
            formatted += sep + ai + '=' + extra[ai];
            sep = '&';
        }
        console.debug("Pre-formatted URI " + formatted)
        return formatted;
    }

    /**
     * Rearranges an un-ordered target GS1 Digital Link URI path expression string to prioritize 
     * specific key qualifiers inside primary path segments.
     * * @static
     * @param {string} string - Generated working draft URI text sequence context.
     * @param {Array<string>} keyQualifiers - Ordered list mapping tracking attributes needing layout promotion.
     * @returns {string} Fully reorganized path layout configuration text block string.
     */
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

        // Group discovered mid-tier string parameter identifiers
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
        // Extract parameters from trailing query string contexts
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

        // Inject active primary descriptors into standard sequential path segments
        for (var aiNum = 0; aiNum < keyQualifiers.length; aiNum++) {
            if (keyQualifiers[aiNum] in found) {
                formatted += '/' + keyQualifiers[aiNum] + '/' + found[keyQualifiers[aiNum]];
            }
        }

        formatted += options;
        console.debug("Post-formatted URI " + formatted)
        return formatted;
    }

    /**
     * Prepends instance pad characters to a string until it reaches a target length limit boundary.
     * * @static
     * @param {string} string - Initial text payload target content.
     * @param {string} padCharacter - Target single padding symbol character.
     * @param {number} finalLength - Minimum output boundary size rule metrics.
     * @returns {string} Modified text block property structure.
     */
    static prePad(string, padCharacter, finalLength) {
        if (string.length < finalLength) {
            string = padCharacter.repeat(finalLength - string.length) + string;
        }
        return string;
    }

    /**
     * Appends instance pad characters to a string until it reaches a target length limit boundary.
     * * @static
     * @param {string} string - Initial text payload target content.
     * @param {string} padCharacter - Target single padding symbol character.
     * @param {number} finalLength - Minimum output boundary size rule metrics.
     * @returns {string} Modified text block property structure.
     */
    static postPad(string, padCharacter, finalLength) {
        if (string.length < finalLength) {
            string += padCharacter.repeat(finalLength - string.length);
        }
        return string;
    }

    // ------------------------------------------------------------------------
    // PRIMITIVE COMPACTION DIGEST ENCODERS (TDS SYSTEM BLOCK ENGINES)
    // ------------------------------------------------------------------------
    
    

    /**
     * Decodes a binary bit stream back into readable text string data using a 
     * fixed bit-width instruction step size.
     * * @static
     * @param {string} inputBinaryString - Sequence consisting strictly of 0 and 1 characters.
     * @param {number} bitsPerChr - Component evaluation segment block step width parameters.
     * @throws {Error} On processing binary syntax faults or incorrect tracking width metrics.
     * @returns {string} Reconstructed plaintext string representation.
     */
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
            // Re-apply standard offset blocks for heavily condensed 5-bit or 6-bit variations
            if ((bitsPerChr == 6 && charCode < 32) || bitsPerChr == 5) {
                charCode += 64;
            }
            if (charCode < 32) break; // Break early if control bounds or termination flags are discovered
            outputCharacterString += String.fromCharCode(charCode);
        }

        return outputCharacterString;
    }

    

    /**
     * Reads a fixed block chunk of a binary stream and returns its decoded decimal string value.
     * * @static
     * @param {string} inputBinaryString - Continuous stream data containing tracking details.
     * @param {Object} options - Active structural definition specification metrics configuration properties.
     * @param {number} options.fixLenBits - Length block processing limits detailing chunk dimensions.
     * @param {number} options.fixLenChrs - Formatting metric instructing required padded character positions.
     * @throws {Error} On passing data strings violating format lengths or character syntax checks.
     * @returns {Object} Tracking properties describing result context maps {"decoded": string, "used": number}.
     */
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

    

    /**
     * Unpacks 20-bit binary encoding of prioritized date values back into their respective 
     * Application Identifier and Date component text strings.
     * * @static
     * @param {string} inputBinaryString - Stream sequence segments containing data parameters.
     * @throws {Error} If length requirements or binary layout boundaries fall short of rules.
     * @returns {Object} Extracted field elements container context maps {"AI": string, "decoded": string, "used": 20}.
     */
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

    

    /**
     * Converts continuous 4-bit binary BCD blocks back into numeric character structures.
     * * @static
     * @param {string} inputBinaryString - Binary data block reference text details.
     * @param {Object} options - Parameter profile structural setup context rules mapping.
     * @param {number} options.fixLenBits - Total expected bit count defining processing limits.
     * @throws {Error} On processing short fields falling below the specified layout requirements.
     * @returns {Object} Parsed string results context object maps {"decoded": string, "used": number}.
     */
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

    

    /**
     * Reverses delimited binary coded decimal (BCD) streams, dynamically switching parsing logic if 
     * character transition markers are identified.
     * * @static
     * @param {string} inputBinaryString - Target string component housing runtime code information.
     * @param {Object} options - Rule metric properties tracking parameters configuration setup.
     * @throws {Error} On layout overflow data checks or tracking flag structural failures.
     * @returns {Object} Decoded results property storage context layout maps {"decoded": string, "used": number}.
     */
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
            } else if (decimal == 15) { // Termination instruction flag '1111'
                if ((t + 4) < inputBinaryString.length) {
                    throw new Error("inputBinaryString contains extra data beyond terminator");
                }
                break;
            } else if (decimal == 14) { // Alphanumeric data layout shift flag '1110'
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

    

    /**
     * Decodes an unaligned variable-width binary sequence back into standard base 10 text.
     * * @static
     * @param {string} inputBinaryString - Stream data array storing execution components.
     * @throws {Error} If context data strings are undefined or contain syntax faults.
     * @returns {string} Restored numerical string context data details.
     */
    static fromBinaryUsingBigInteger(inputBinaryString) {
        if (inputBinaryString === undefined) {
            throw new Error("input string is undefined");
        }

        if (!TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("input " + inputBinaryString + " is not binary - only bit 0 or 1 allowed");
        }

        return BigInt('0b' + inputBinaryString).toString();
    }

    

    /**
     * Decodes binary stream sequences into uppercase hexadecimal string representations.
     * * @static
     * @param {string} inputBinaryString - Base data chunk records.
     * @throws {Error} On passing streams whose length is not a clean multiple of 4 bits.
     * @returns {string} Standard uppercase hexadecimal string data context.
     */
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

    

    /**
     * Decodes binary stream sequences into lowercase hexadecimal string representations.
     * * @static
     * @param {string} inputBinaryString - Base data chunk records.
     * @throws {Error} On passing streams whose length is not a clean multiple of 4 bits.
     * @returns {string} Standard lowercase hexadecimal string data context.
     */
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

    /**
     * Encodes file-safe URL-safe base64 character blocks into continuous 6-bit binary segments.
     * * @static
     * @param {string} inputCharacterString - URL-safe base64 data string.
     * @throws {Error} If character content violates standardized base64 tracking alphabets.
     * @returns {string} Compiled binary data streams.
     */
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

    

    

    /**
     * Translates 16-bit binary block intervals back into standard URN Code 40 strings.
     * * @static
     * @param {string} inputBinaryString - Stream data sequence containing tracking fields.
     * @throws {Error} If block structures are not clean multiples of 16 bits.
     * @returns {string} Clean trimmed plain text character string parameters.
     */
    static fromBinaryUsingURNcode40(inputBinaryString) {
        if (!inputBinaryString || !TDTtranslator.regexBinaryString.test(inputBinaryString)) {
            throw new Error("input is not binary - only bit 0 or 1 allowed");
        }

        let outputCharacterString = "";
        if (inputBinaryString.length % 16 == 0) {
            for (let t = 0; t < (inputBinaryString.length / 16); t++) {
                const substr = inputBinaryString.substr(16 * t, 16);
                const n = parseInt(substr, 2);
                // Extract individual characters via inverse polynomial base-40 arithmetic
                const c3 = (n - 1) % 40;
                const c2 = (((n - 1) - c3) / 40) % 40;
                const c1 = (n - 1 - c3 - 40 * c2) / 1600;
                outputCharacterString += TDTtranslator.alphabetURNcode40.charAt(c1) + TDTtranslator.alphabetURNcode40.charAt(c2) + TDTtranslator.alphabetURNcode40.charAt(c3);
            }
            outputCharacterString = outputCharacterString.split(" ").join(""); // Strip residual padding space allocations
            return outputCharacterString;
        } else {
            throw new Error("Input is not an exact multiple of 16 bits");
        }
    }

    

    /**
     * Decodes 7-bit binary chunks back into readable ASCII text string data.
     * * @static
     * @param {string} inputBinaryString - Continuous stream content parameters.
     * @returns {string} Restored plain text data results.
     */
    static fromBinaryUsingSevenBitASCII(inputBinaryString) {
        return TDTtranslator.fromBinaryUsingTruncatedASCII(inputBinaryString, 7);
    }

    /**
     * Static property getter mapping available structural options for alphanumeric 
     * variable data encoding methods. Used to dynamically assess bit efficiency.
     * * @static
     * @type {Array<Object>} Collection detailing capabilities metrics across encoding variants.
     */
    static get encodingOptionsAlphanumeric() {
        return [
            {"regex":TDTtranslator.regexSevenBit, "indicator": "100","text":"7-bit ASCII","num":7,"denom":1,"encoder": TDTtranslator.toBinaryUsingSevenBitASCII , "decoder": TDTtranslator.fromBinaryUsingSevenBitASCII},
            {"regex":TDTtranslator.regexFileSafeURISafeBase64, "indicator": "011","text":"file-safe URI-safe base 64","num":6,"denom":1,"encoder": TDTtranslator.toBinaryUsingFileSafeURISafeBase64,"decoder": TDTtranslator.fromBinaryUsingFileSafeURISafeBase64},
            {"regex":TDTtranslator.regexLowerCaseHexadecimal, "indicator": "010","text":"lower case hexadecimal","num":4,"denom":1,"encoder": TDTtranslator.toBinaryUsingLowerCaseHexadecimal , "decoder": TDTtranslator.fromBinaryUsingLowerCaseHexadecimal},
            {"regex":TDTtranslator.regexUpperCaseHexadecimal, "indicator": "001","text":"upper case hexadecimal","num":4,"denom":1,"encoder": TDTtranslator.toBinaryUsingUpperCaseHexadecimal , "decoder": TDTtranslator.fromBinaryUsingUpperCaseHexadecimal},
            {"regex":TDTtranslator.regexAllNumeric, "indicator": "000","text":"All-numeric","num":Math.log(10),"denom":Math.log(2),"encoder": TDTtranslator.toBinaryUsingBigInteger,"decoder": TDTtranslator.fromBinaryUsingBigInteger},
            {"regex":TDTtranslator.regexURNcode40, "indicator": "101","text":"URN Code 40","num":16,"denom": 3,"encoder": TDTtranslator.toBinaryUsingURNcode40,"decoder": TDTtranslator.fromBinaryUsingURNcode40}
        ];
    }

    /**
     * Sorting comparator tracking properties to prioritize encoders with the 
     * smallest generated output bit requirements.
     * * @static
     * @param {Object} a - Left evaluation candidate context element.
     * @param {Object} b - Right evaluation candidate context element.
     * @returns {number} Directional weight metrics instruction flags (-1, 1, or 0).
     */
    static byAscendingBitCount(a, b) {
        if (a.bitCount < b.bitCount) { return -1; }
        if (a.bitCount > b.bitCount) { return 1; }
        return a.indicator > b.indicator ? 1 : -1 ;
    }

    

    /**
     * Reads a variable-length alphanumeric bitstream block, dynamically detecting the 
     * encoding format from the prefix indicator to route it to the correct decoder.
     * * @static
     * @param {string} inputBinaryString - Stream data sequence housing tracking profiles.
     * @param {Object} options - Parameter context metrics definitions configurations.
     * @param {number} options.lenIndBits - Sizing details mapping the bit-width of length indicators.
     * @throws {Error} If stream strings are undefined or contain syntax faults.
     * @returns {Object} Comprehensive tracking results context maps {"decoded": string, "used": number}.
     */
    static fromBinaryUsingVariableLengthAlphanumeric(inputBinaryString, options) {
        let rv = {};
        rv.used = 0;

        if ((inputBinaryString !== undefined) && (TDTtranslator.regexBinaryString.test(inputBinaryString))) {
            let encodingIndicator = inputBinaryString.substr(0, 3);
            rv.used += 3;
            let length = parseInt(inputBinaryString.substr(3, options.lenIndBits), 2);
            rv.used += options.lenIndBits;

            // Identify the corresponding decoder strategy via its indicator signature code
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

    

    /**
     * Reads a single bit from a binary stream.
     * * @static
     * @param {string} inputBinaryString - Stream block container context data.
     * @throws {Error} If the initial bit location contains invalid layout symbols.
     * @returns {Object} Extracted block components map context {"decoded": string, "used": 1}.
     */
    static fromBinaryUsingSingleDataBit(inputBinaryString) {
        if (!TDTtranslator.regexSingleBit.test(inputBinaryString.substr(0, 1))) {
            throw new Error(`Input ${inputBinaryString} does not match regex for a single bit (0 or 1)`);
        }
        return {
            "decoded": inputBinaryString.substr(0, 1),
            "used": 1
        };
    }

    

    /**
     * Unpacks a 16-bit binary data block back into a standard six-digit `YYMMDD` date string.
     * * @static
     * @param {string} inputBinaryString - Core source bit sequence.
     * @throws {Error} On passing streams shorter than 16 bits or containing invalid date parameters.
     * @returns {Object} Reconstructed tracking result property containers {"decoded": string, "used": 16}.
     */
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

    

    /**
     * Unpacks a 27-bit binary data block back into a standard ten-digit timestamp string (`YYMMDDhhmm`).
     * * @static
     * @param {string} inputBinaryString - Stream array elements containing data profiles.
     * @throws {Error} If stream sizes are too short or contain values violating standard calendar limits.
     * @returns {Object} Extracted string properties collection mappings {"decoded": string, "used": 27}.
     */
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

    

    /**
     * Decodes a binary block containing a singular date or date range.
     * Uses the initial flag bit to dynamically adapt the expected bit-length footprint.
     * * @static
     * @param {string} inputBinaryString - Data string containing raw bits.
     * @throws {Error} On short stream sizes, syntax errors, or components breaking calendar limits.
     * @returns {Object} Consolidated text properties context map {"decoded": string, "used": number}.
     */
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

        // Process the secondary date blocks if the date range flag bit was active
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

    

    /**
     * Decodes a variable-precision binary timestamp block.
     * Parses the leading 2-bit precision prefix to determine how many bits to consume.
     * * @static
     * @param {string} inputBinaryString - Stream sequence segments text.
     * @throws {Error} On short stream allocations, formatting errors, or components breaking calendar limits.
     * @returns {Object} Extracted data properties collection tracking metrics {"decoded": string, "used": number}.
     */
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

        // Extract hour block details if precision rules allow
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

        // Extract minute block details if precision rules allow
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

        // Extract second block details if precision rules allow
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

    

    /**
     * Unpacks a 12-bit binary segment back into a readable two-letter ISO 3166 country code string.
     * * @static
     * @param {string} inputBinaryString - Stream chunk storing execution details.
     * @throws {Error} If data targets are undefined or contain fewer than 12 bits of information.
     * @returns {Object} Extracted field elements mapping configuration properties {"decoded": string, "used": 12}.
     */
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

    

    /**
     * Decodes a variable-length binary numeric field block by reading the length indicator prefix.
     * * @static
     * @param {string} inputBinaryString - Bit sequence data tracking segments.
     * @param {Object} options - Parameters context object map schema configuration targets.
     * @param {number} options.lenIndBits - Allocated width in bits of the length indicator prefix.
     * @returns {Object} Tracking properties describing results {"decoded": string, "used": number}.
     */
    static fromBinaryUsingVariableLengthNumeric(inputBinaryString, options) {
        let length = parseInt(inputBinaryString.substr(0, options.lenIndBits), 2);
        const bitLength = Math.ceil(Math.log2(Math.pow(10, length) - 1));
        return {
            "decoded": TDTtranslator.prePad(TDTtranslator.fromBinaryUsingBigInteger(inputBinaryString.substr(options.lenIndBits, bitLength)), "0", length),
            "used": options.lenIndBits + bitLength
        };
    }

    

    /**
     * Decodes a single bit into an optional minus sign character or an empty string.
     * * @static
     * @param {string} inputBinaryString - Stream data collection source text details.
     * @throws {Error} If processing data fields violating structural layout regex rules.
     * @returns {Object} Extracted data property tracking metrics {"decoded": string, "used": 1}.
     */
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
    
    /**
     * Look-up table connecting TDS standard compression specification references 
     * directly to their respective validation expressions and compaction codec engines.
     * @static
     * @type {Object} Registry dictionary tracking compaction codec pairings.
     */
    static get tds2encodingMethods() {
        return {
            "14.5.2": { "regex": TDTtranslator.regexAllNumeric, "decoder": TDTtranslator.fromBinaryUsingFixedBitLengthInteger },
            "14.5.3": {},
            "14.5.4": { "regex": TDTtranslator.regexAllNumeric, "decoder": TDTtranslator.fromBinaryUsingFixedLengthNumeric },
            "14.5.5": { "regex": TDTtranslator.regexAlphanumeric, "decoder": TDTtranslator.fromBinaryUsingDelimitedNumeric },
            "14.5.6": { "regex": TDTtranslator.regexAlphanumeric, "decoder": TDTtranslator.fromBinaryUsingVariableLengthAlphanumeric },
            "14.5.7": { "regex": TDTtranslator.regexSingleBit, "decoder": TDTtranslator.fromBinaryUsingSingleDataBit },
            "14.5.8": { "regex": TDTtranslator.regexDateYYMMDD, "decoder": TDTtranslator.fromBinaryUsingDateYYMMDD },
            "14.5.9": { "regex": TDTtranslator.regexDateYYMMDDhhmm, "decoder": TDTtranslator.fromBinaryUsingDateYYMMDDhhmm },
            "14.5.10": { "regex": TDTtranslator.regexDateYYMMDDorYYMMDDYYMMDD, "decoder": TDTtranslator.fromBinaryUsingDateOrDateRange },
            "14.5.11": { "regex": TDTtranslator.regexVariablePrecisionDateTimeYYMMDDhh_mmss, "decoder": TDTtranslator.fromBinaryUsingVariablePrecisionDateTime},
            "14.5.12": { "regex": TDTtranslator.regexCountryCode, "decoder": TDTtranslator.fromBinaryUsingCountryCode },
            "14.5.13": { "regex": TDTtranslator.regexAllNumeric, "decoder": TDTtranslator.fromBinaryUsingVariableLengthNumeric },
            "14.5.14": { "regex": TDTtranslator.regexOptionalMinus, "decoder": TDTtranslator.fromBinaryUsingOptionalMinus }
        };
    }

    /**
     * Generic structural routing interface that resolves the correct decompression codec 
     * to decode binary bitstream chunks based on configuration instructions parsed from Table F.
     * * @static
     * @param {string} inputBinaryString - Stream data collection segments text details.
     * @param {Object} options - Specification definitions metadata profiling instruction parameters.
     * @param {string} options.section - Selected TDS spec section tracking lookup key.
     * @throws {Error} If matching decompression configuration parameters are missing from index logs.
     * @returns {Object} Result properties object tracking context metrics {"characterString": string, "used": number}.
     */
    static fromBinaryUsingTableF(inputBinaryString, options) {
        const rv = {};

        if (!TDTtranslator.tds2encodingMethods[options.section]) {
            throw new Error("Encoding method not found for " + JSON.stringify(options.section));
        } else {
            rv.encodingMethod = TDTtranslator.tds2encodingMethods[options.section];
            // Execute decoding using the resolved specification section component
            let dec = rv.encodingMethod.decoder(inputBinaryString, options);
            rv.characterString = dec.decoded;
            rv.used = dec.used;
            return rv;
        }
    }

    // ------------------------------------------------------------------------
    // PURE FUNCTIONAL PLUSDATA EXTRACTORS AND ENCODERS
    // ------------------------------------------------------------------------
    
    

    /**
     * Decodes the remaining trailing segment of a binary stream to extract peripheral data components 
     * (+AIDC / Plus Data) by evaluating lookup definitions from Table F and Table K.
     * * @static
     * @param {string} inputBinaryString - Trailing chunk array text derived from the primary execution thread.
     * @param {Object} tablef - Operational specifications reference map parsed from schema catalogs.
     * @param {Object} tablek - Data key prefix dimensions mapping context dictionary parameters.
     * @throws {Error} On parsing unmapped syntax keys, broken layout layers, or invalid indicators.
     * @returns {Array<Object>} Collection of extracted peripheral data structures [{"ai": string, "value": string}].
     */
    static fromBINARYExtractPlusData(inputBinaryString, tablef, tablek) {
        let plusData = [];

        if (inputBinaryString.length < 8) {
            return plusData;
        }
        // Iterate through the bitstream chunk systematically to extract data attributes
        while (inputBinaryString.length > 8) {
            let ai = parseInt(inputBinaryString.substr(0, 4), 2).toString();
            ai += parseInt(inputBinaryString.substr(4, 4), 2).toString();
            if (!/^[0-9]{2}$/.test(ai)) {
                throw new Error("Invalid decoded AI " + ai);
            }
            inputBinaryString = inputBinaryString.substr(8);

            // Handle special execution conditions matching empty termination fields
            if (ai == "00" && inputBinaryString.length < 72) return plusData;

            let tableKrow = tablek[ai];
            if (!tableKrow) {
                throw new Error("Invalid AI prefix decoded " + ai);
            }
            // Conditionally process variable application identifiers with lengths greater than 2 digits
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
                // Decode the initial core value sub-component using Table F instructions
                let decoded = TDTtranslator.fromBinaryUsingTableF(inputBinaryString, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });
                value += decoded.characterString;
                inputBinaryString = inputBinaryString.substr(decoded.used);
                
                // Decode the secondary value sub-component if outlined in Table F
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
    /**
     * Extracts peripheral key-value pairs (+AIDC / Plus Data) from JSON-formatted string representations.
     * @static
     * @param {string} inputJSONString - Incoming JSON payload structure text.
     * @param {Array<string>} aiSequence - Core specification parameters to skip during collection processing.
     * @returns {Array<Object>} List housing separated key-value metadata maps [{"ai": string, "value": string}].
     */
    static fromJSONExtractPlusData(inputJSONString, aiSequence) {
        const parsed = JSON.parse(inputJSONString);
        let plusData = [];

        for (let ai of Object.keys(parsed)) {
            // Omit core identifier properties to preserve only peripheral data elements
            if (aiSequence.includes(ai)) {
                continue;
            }
            plusData.push({"ai": ai, "value": parsed[ai]});
        }
        return plusData;
    }

    /**
     * Parses the trailing query parameters of a Web URL string to isolate 
     * peripheral key-value pairs (+AIDC / Plus Data).
     * @static
     * @param {string} inputDLString - Source text tracking trailing URL query strings.
     * @returns {Array<Object>} List storing extracted peripheral properties [{"ai": string, "value": string}].
     */
    static fromDigitalLinkExtractPlusData(inputDLString) {
        let re = new RegExp(/^(([0-9]{2,4})=([A-Za-z0-9%"._-]+)(&|$)?)/);
        let matches = [];
        let plusData = [];
        // Iterate through query parameter key-value pairs systematically
        while (matches = inputDLString.match(re)) {
            inputDLString = inputDLString.substr(matches[0].length);
            plusData.push({"ai": matches[2], "value": decodeURIComponent(matches[3])});
        }
        console.debug(JSON.stringify(plusData, null, 2))
        return plusData;
    }

    /**
     * Encodes peripheral data structures (+AIDC / Plus Data) into their optimal binary representations 
     * by resolving and applying structural format specifications from Table F.
     * @static
     * @param {Array<Object>} plusdata - List housing peripheral data metadata maps.
     * @param {Object} tablef - Configuration metadata specification references context directory log.
     * @param {boolean} returnArray - Flag to return a diagnostic layout array instead of a flat string.
     * @returns {string|Array<Array<string>>} Flat binary sequence text string, or a two-part array containing diagnostic components.
     */
    static toBINARYEncodePlusData(plusdata, tablef, returnArray) {
        let rv = [];
        let rvComponents = [];
        for (let data of plusdata) {
            let tableFrow = tablef[data.ai];
            if (tableFrow) {
                console.debug("TableF row for AI (" + data.ai + "): " + JSON.stringify(tableFrow, null, 2));

                // Convert the Application Identifier label into a standard 4-bit BCD string segment
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
                
                // Encode the primary value component using Table F configuration rules
                let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });

                plusDataOutput.push(b.binary);

                // Encode the secondary value component if specified in Table F configuration rules
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
        // Conditionally return diagnostic parameters or flat bitstream data structures
        if (returnArray) {
            return [rv, rvComponents];
        }
        return rv.join("");
    }

    /**
     * Serializes peripheral data structures (+AIDC / Plus Data) into partial comma-separated 
     * JSON text attributes.
     * @static
     * @param {Array<Object>} plusdata - Source array storing structured data elements.
     * @returns {string} Serialized JSON attribute string segments.
     */
    static toJSONEncodePlusData(plusdata) {
        let encoded = "";
        for (let data of plusdata) {
            encoded += ',"' + data.ai + '":';
            let json = JSON.stringify(data.value);
            encoded += json;
        }
        return encoded;
    }
    

    /**
     * Serializes peripheral data structures (+AIDC / Plus Data) into ampersand-delimited 
     * URL query parameter segments.
     * * @static
     * @param {Array<Object>} plusdata - Source array storing structured data elements.
     * @returns {string} Query string segment text parameters.
     */
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
    
    
    
    /**
     * Inspects incoming tracking strings against cached regular expressions to dynamically identify 
     * the source EPC scheme format, processing level, and matching parameters.
     * * @param {string} inputString - Target unknown source sequence data text or hexadecimal stream.
     * @returns {Array<Object>} List housing discovery metric items describing structural characteristics.
     */
    autodetect(inputString) {
        if (!this.tdtData || !this.tdtData.scheme) {
             console.error('Data not available yet. Please wait for initialization.');
             return [];
        }

        const compressedMatch = inputString.match(/^(https?:\/\/[^\/]+.*?\/)e([hx])([0-9A-Za-z_-]+)$/);
        let isCompressed = false;
        if (compressedMatch) {
            isCompressed = true;
            const flag = compressedMatch[2];
            const dataStr = compressedMatch[3];
            if (flag === 'h') {
                inputString = this.hex2bin(dataStr);
            } else {
                inputString = TDTtranslator.toBinaryUsingFileSafeURISafeBase64(dataStr);
            }
        }

        let rv = []
        let isHex = false;
        // Inwardly cast raw hexadecimal inputs into operational binary strings
        if (TDTtranslator.regexHexadecimal.test(inputString) && !TDTtranslator.regexBinaryString.test(inputString)) {
            console.debug("Detected hex input");
            inputString = this.hex2bin(inputString);
            isHex = true;
        }
        
        // Scan each known scheme configuration systematically to locate matching structural parameters
        for (let s of Object.keys(this.tdtData.scheme)) {
            let optionKey = this.tdtData.scheme[s][TDTtranslator.tdtDataContainer].scheme.optionKey
            let levels = [];
            for (let level of this.tdtData.scheme[s][TDTtranslator.tdtDataContainer].scheme.level) {
                levels.push(level.type);
            }
            // Evaluate current text rules against scheme option pattern configurations
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
                            // Dynamically look up the matching prefix length tracking rule parameters
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
                                    prefixLen = -1;
                                    break;
                                }
                                case "BINARY":
                                case "TAG_ENCODING":
                                case "PURE_IDENTITY": {
                                    if (optionKey == "gs1companyprefixlength") prefixLen = parseInt(o.optionKey);
                                    break;
                                }
                            }

                            // Discard variations that mismatch evaluated prefix length tracking metrics
                            if (optionKey === "gs1companyprefixlength" && prefixLen !== -1 && prefixLen !== parseInt(o.optionKey)) {
                                continue; 
                            }
    
                            let detectedLevel = sl.type;
                            if (isCompressed && sl.type === "BINARY") {
                                detectedLevel = "COMPRESSED_GS1_DIGITAL_LINK";
                            }
                            rv.push({"scheme":s,"level":(isHex && (detectedLevel == "BINARY") ? "HEX" : detectedLevel),"optionKey": {"property": optionKey, "value": o.optionKey}, "supportedLevels": levels, "detectedGCPLength": prefixLen});
                        }
                    }
                }
            }
        }
        return rv;
    }

    /**
     * Master Translation Runtime Orchestrator Pipeline.
     * Manages token parsing, macro execution, bit compaction packing, and final output assembly.
     * * @param {string} inputString - Core target message context data text segment requiring translation.
     * @param {string} scheme - Identified target tracking schema identifier catalog entry (e.g., 'sgtin').
     * @param {string} outputLevel - Requested output formatting destination layer profile (e.g., 'BINARY', 'GS1_DIGITAL_LINK').
     * @param {Object} [options={}] - Custom parameter override settings passed to execution context frames.
     * @throws {TDTExtractionError} On pattern validation failures or unparseable input structures.
     * @throws {Error} On unmapped state errors or invalid argument configurations.
     * @returns {string|Array} Standard conversion response string, or structural matrix tracking components arrays.
     */
    translate(inputString, scheme, outputLevel, options = {}) {
        let internalMap = {};
        let outputLevelData = null;
        let hexOut = false;

        if (!this.tdtData || !this.tdtData.scheme) {
            throw new Error('System State Error: Engine processing called prior to data repository realization.');
        }

        const compressedMatch = inputString.match(/^(https?:\/\/[^\/]+.*?\/)e([hx])([0-9A-Za-z_-]+)$/);
        if (compressedMatch) {
            let extractedUriStem = compressedMatch[1];
            if (extractedUriStem.endsWith('/')) {
                extractedUriStem = extractedUriStem.slice(0, -1);
            }
            const flag = compressedMatch[2];
            const dataStr = compressedMatch[3];
            if (flag === 'h') {
                inputString = this.hex2bin(dataStr);
            } else {
                inputString = TDTtranslator.toBinaryUsingFileSafeURISafeBase64(dataStr);
            }
            options.uriStem = extractedUriStem;
        }

        console.debug("Request to translate " + inputString + " to " + outputLevel + " using options " + JSON.stringify(options));

        if (!this.tdtData.scheme.hasOwnProperty(scheme)) {
            console.error("Un-supported EPC scheme " + scheme);
            return;
        }

        // Standardize input streams immediately by converting hex values to binary strings
        if (TDTtranslator.regexHexadecimal.test(inputString) && !TDTtranslator.regexBinaryString.test(inputString)) inputString = this.hex2bin(inputString);

        let optionKey = this.tdtData.scheme[scheme][TDTtranslator.tdtDataContainer].scheme.optionKey;

        // Set hex conversion routing triggers if requested as the final output format
        if (outputLevel == 'HEX') {
            hexOut = true;
            outputLevel = 'BINARY';
        }

        console.debug("Auto-detecting input level");
        let foundMatch = false;
        
        // Locate matching input patterns across available scheme configuration rules
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
                    
                    // Route parsed text elements into internal storage maps
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

                    // Isolate raw hostname bitstreams from high-density extensions (e.g., PlusPlus schemas)
                    if (level.type === "BINARY" && matchGroups && matchGroups[lastSeq + 1] && (scheme.includes("++") || scheme.toLowerCase().includes("plusplus"))) {
                        internalMap["binaryHostname"] = matchGroups[lastSeq + 1];
                        internalMap["_trailingBits"] = matchGroups[lastSeq + 1];
                    }
 
                    // Unpack trailing components according to source format layers
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

                // Execute declarative extraction macro functions sequentially
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

                // Process remaining bit segments to extract trailing peripheral attributes
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

                // Precedence rule enforcement: Use custom hostname variables over standard URI stems if present
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

        // Toggle configuration tracking markers based on peripheral data availability
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
        
        // Validate required formatting parameters before beginning output generation
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

        // Execute declarative formatting macro rules sequentially
        if (outputLevelData.hasOwnProperty("rule")) {
            let outputComponents = outputOption.grammar.match(/('.*?'|[^'\s]+)(?=\s|\s*$)/g);
            console.debug("Processing FORMAT rules");
            
            // Align data structures across PlusPlus architecture rules to support custom hostnames
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

        // Pack specified application identifier variables into output target structures
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

        // Assemble the final output components following the rules of the selected output grammar
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

        // Encode peripheral variables (+AIDC / Plus Data) back into target output formats if present
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
                    outputArrayEntries.push('+AIDC');
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
                    outputArrayEntries.push('+AIDC');
                    break;
                }
            }
        }

        console.debug("finalOutputArray = " + JSON.stringify(finalOutputArray));
        let returnString = finalOutputArray.join("");

        // Execute final sorting logic if translating to standard GS1 Digital Link patterns
        if ((outputLevel == "GS1_DIGITAL_LINK") && (outputLevelData.gs1DigitalLinkKeyQualifiers.length > 0)) {
            returnString = TDTtranslator.digitalLinkPostFormat(returnString, outputLevelData.gs1DigitalLinkKeyQualifiers);
        }

        // Transform results to hexadecimal text strings if requested by the final output trigger
        if (hexOut) returnString = this.bin2hex(returnString);

        console.debug("output string = " + returnString);
        if (options.hasOwnProperty('returnArray') && (options['returnArray'])) {
            return [finalOutputArray, outputArrayEntries];
        } else {
            return returnString;
        }
    }

    

    

    /**
     * Utility method to convert hexadecimal text string blocks into plain binary streams.
     * * @param {string} inputHexString - Target string housing hexadecimal data parameters.
     * @throws {Error} If fields contain symbols outside valid hex boundaries.
     * @returns {string} Continuous binary bitstream string.
     */
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

    /**
     * Static filter function factory providing predicates to map entries by filename parameters.
     * * @private
     * @static
     * @param {string} filename - Target document label lookup path.
     * @returns {Function} Predicate verification handler logic.
     */
    static #byFile(filename) {
        return function (element) {
            if (element['file'] == filename) { return true; }
        }
    }

    /**
     * Extracts and unpacks targeted JSON data from dynamic file list objects.
     * * @private
     * @static
     * @param {Array<Object>} data - Source repository collection matrix context.
     * @param {string} key - Specific configuration index lookup path identifier.
     * @returns {Object|Array} Unpacked native configuration data.
     */
    static #unwrapDataByFilename(data, key) {
        return data.filter(TDTtranslator.#byFile(key))[0].data;
    }

}

// Map globally exposed utility components back to the constructor interface flawlessly
TDTtranslator.prePad = TDTtranslator.prePad;
TDTtranslator.fromBinaryUsingTableF = TDTtranslator.fromBinaryUsingTableF;