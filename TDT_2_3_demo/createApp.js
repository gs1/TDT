/**
 * @fileoverview GS1 TDS / TDT 2.x Application Controller.
 * Leverages the Vue.js v3 Options API and native plain CSS to drive an interactive,
 * high-throughput validation and translation workbench for Electronic Product Code (EPC)
 * and GS1 Digital Link standard formats.
 */

/**
 * Immutable string samples representing acceptable input patterns.
 * @type {Readonly<{json: string, digitalLink: string, binary: string, hex: string, tagUrn: string, pureUrn: string, bareKv: string}>}
 */
const DEMO_VALUES = Object.freeze({
	json: '{"01":"09521234123453", "21":"32a/b"}',
	digitalLink: 'https://id.gs1.org/01/09521234123453/21/32a%2Fb',
	customDomain: 'https://id.abcde.com/01/01234567890128/21/987XYZ',
	binary: '111101111000100101010010000101000011001010000101000101110011011001000000010100011000000111001000101110010110010111111',
	hex: 'F73095212341234538566CB0AFC4',
	tagUrn: 'urn:epc:tag:sgtin-198:0.9521234.012345.32a%2F',
	pureUrn: 'urn:epc:id:sgtin:9521234.012345.32a%2Fb',
	bareKv: 'gtin=09521234123453;serial=32a/b'
});

/**
 * Friendly structural syntax level titles mapping.
 * @type {Readonly<Object<string, string>>}
 */
const LEVEL_NAMES = Object.freeze({ 
	"BINARY": "Binary encoded TDS data", 
	"HEX": "Hex encoded TDS data", 
	"GS1_AI_JSON": "GS1 AI String in JSON", 
	"GS1_DIGITAL_LINK": "GS1 Digital Link URI", 
	"COMPRESSED_GS1_DIGITAL_LINK": "Compressed GS1 Digital Link URI", 
	"TAG_ENCODING": "EPC Tag URI", 
	"PURE_IDENTITY": "EPC Pure URI", 
	"BARE_IDENTIFIER": "Bare Identifier", 
	"TEI": "Text Element Identifier"
});

/**
 * Processing formats capable of reading or providing GS1 Company Prefix boundaries natively.
 * @type {ReadonlyArray<string>}
 */
const SCHEMES_PROVIDING_GCP = Object.freeze(["BINARY", "TAG_ENCODING", "PURE_IDENTITY"]);

/**
 * Master mapping reference defining readable labels for prioritized dateType flags.
 * Used when multi-variant schemas depend on specified date identifiers.
 * @type {Readonly<Object<string, string>>}
 */
const DATE_TYPE_MAP = Object.freeze({
	"0": "prioritised date: Production Date / GS1 AI (11)",
	"1": "prioritised date: Packaging Date / GS1 AI (13)",
	"2": "prioritised date: Best Before Date / GS1 AI (15)",
	"3": "prioritised date: Sell By Date / GS1 AI (16)",
	"4": "prioritised date: Expiration Date / GS1 AI (17)",
	"5": "prioritised date: First Freeze Date / GS1 AI (7006)",
	"6": "prioritised date: Harvest Date Range / GS1 AI (7007)"
});

const { createApp, markRaw } = Vue;

createApp({
	/**
	 * Component state properties.
	 * @returns {{
	 * myTDTencoder: Object|null, isInitialized: boolean, inputString: string,
	 * filter: number, gcpLength: number, gcpOverride: boolean, uriStem: string,
	 * gcpMessage: string, activeCopiedKey: string, demoValues: Object, levelNames: Object
	 * }}
	 */
	data() {
		return {
			myTDTencoder: null,
			isInitialized: false,
			inputString: '',
			filter: 0,
			gcpLength: 7,
			gcpOverride: false,
			uriStem: 'https://id.gs1.org',
			gcpMessage: '',
			activeCopiedKey: '',
			demoValues: DEMO_VALUES,
			levelNames: LEVEL_NAMES
		}
	},

	watch: {
		/**
		 * Handles reactive state shifts based on input structural variations.
		 * Decouples updates away from computed property evaluators to safeguard runtime execution.
		 * @param {Object|null} newData - The modified evaluation matrix.
		 */
		detectedData(newData) {
			if (!newData || newData.error || !newData.detected || newData.detected.length === 0) {
				if (!this.gcpOverride) {
					this.gcpMessage = '';
				}
				return;
			}

			const primaryMatch = newData.detected[0];
			if (primaryMatch.detectedGCPLength > 0 && !this.gcpOverride) {
				this.gcpLength = primaryMatch.detectedGCPLength;
				this.gcpMessage = "Using auto-detected GCP length";
			} else if (!this.gcpOverride) {
				this.gcpMessage = '';
			}
		}
	},

	computed: {
		/**
		 * Runs core lookup matching arrays against the current input string using the translator engine.
		 * @returns {Object|null} Array of identified schema matches or an error payload object.
		 */
		detectedData() {
			if (!this.isInitialized || !this.inputString) return null;
			try {
				let detected = this.myTDTencoder.autodetect(this.inputString);
				if (!detected || detected.length === 0) return { error: 'Failed to match input to any TDS scheme' };
				return { detected, level: detected[0].level };
			} catch(e) {
				return { error: e.toString() };
			}
		},

		/**
		 * Surface-level validation error inspector.
		 * @returns {string|null} The error message, if validation fails.
		 */
		globalError() {
			return this.detectedData && this.detectedData.error ? this.detectedData.error : null;
		},

		/**
		 * Form factor representation mapping key for the recognized source string.
		 * @returns {string} Target token matching architectural level constants.
		 */
		inputLevel() {
			return this.detectedData && this.detectedData.level ? this.detectedData.level : '';
		},

		/**
		 * Builds the data translation structures for all candidate schemes matching the input string.
		 * @returns {Array<{
		 * id: string, extraText: string, bitCount: number, isLossless: boolean,
		 * levels: Array<{type: string, textContent: string, htmlContent: string, rawValue: string, meta: string}>
		 * }>} Complete list of mapped scheme options and their corresponding output formats.
		 */
		structuredSchemes() {
			if (!this.detectedData || this.detectedData.error) return [];
			
			const detectedList = this.detectedData.detected;
			const encoder = this.myTDTencoder;
			const structures = [];

			/**
			 * Assesses lossless identity mapping requirements for non-standard URI domain names.
			 * @param {string} inputStr - Raw evaluation value string.
			 * @param {string} currentLevel - Format type token identifier.
			 * @param {string} schemeId - Active scheme candidate structure name.
			 * @returns {boolean} True if structural parameters ensure safe bidirectional mapping.
			 */
			const checkLosslessStatus = (inputStr, currentLevel, schemeId) => {
				if (currentLevel !== 'GS1_DIGITAL_LINK') return true;
				try {
					const urlObj = new URL(inputStr);
					if (urlObj.hostname !== 'id.gs1.org') {
						return schemeId.includes('++') || schemeId.toLowerCase().includes('plusplus');
					}
				} catch (e) {
					if (inputStr.toLowerCase().startsWith('http')) {
						const stripped = inputStr.replace(/^https?:\/\//i, '').split('/')[0];
						if (stripped && stripped !== 'id.gs1.org') {
							return schemeId.includes('++') || schemeId.toLowerCase().includes('plusplus');
						}
					}
				}
				return true;
			};

			for (const match of detectedList) {
				let extraText = "";
				if (match.optionKey.property) {
					const targetProp = match.optionKey.property;
					const targetVal = match.optionKey.value;
					if (targetProp === "dateType" && DATE_TYPE_MAP[targetVal]) {
						extraText = `, ${DATE_TYPE_MAP[targetVal]}`;
					} else if (targetProp !== targetVal) {
						extraText = `, ${targetProp}: ${targetVal}`;
					}
				}

				const schemeItem = {
					id: match.scheme,
					extraText: extraText,
					levels: [],
					bitCount: 0,
					isLossless: checkLosslessStatus(this.inputString, this.inputLevel, match.scheme)
				};

				// Reusable reference setup limits initialization allocations inside the deep iteration paths
				const baseOptions = { 
					filter: this.filter, 
					uriStem: this.uriStem, 
					gs1companyprefixlength: this.gcpLength 
				};

				if (match.optionKey.property === "gs1companyprefixlength") {
					if (SCHEMES_PROVIDING_GCP.includes(this.inputLevel)) {
						baseOptions.gs1companyprefixlength = match.optionKey.value;
					}
				} else if (match.optionKey.property && (match.optionKey.property !== match.optionKey.value)) {
					baseOptions[match.optionKey.property] = match.optionKey.value;
				}

				for (const targetLevel of match.supportedLevels) {
					const options = { ...baseOptions };

					try {
						if ((targetLevel === "BINARY") && (this.inputLevel !== "HEX")) {
							const hexTranslated = encoder.translate(this.inputString, match.scheme, "HEX", options);
							schemeItem.levels.push({
								type: 'HEX',
								textContent: hexTranslated,
								rawValue: hexTranslated
							});
						}

						if (targetLevel === this.inputLevel) {
							if (targetLevel === 'BINARY') {
								schemeItem.bitCount = this.inputString.length;
							}
							continue;
						}
						
						let translated = '';
						let htmlContent = '';
						let metadataInfo = '';

						if (targetLevel === "BINARY") {
							options.returnArray = true;
							const [outputArray, arrayEntries] = encoder.translate(this.inputString, match.scheme, targetLevel, options);
							options.returnArray = false;
							
							// Transforms the bit values into a scannable, color-coded structure
							htmlContent = outputArray.map((bitValue, index) => {
								const styleClassIndex = index % 10;
								const entryName = (index === 0 && (arrayEntries[index] === 'literal' || bitValue.length === 8)) ? 'EPC Header' : arrayEntries[index];
								return `<span class="binary binary${styleClassIndex}" title="${entryName}">${bitValue}</span>`;
							}).join("");

							translated = outputArray.join("");
							schemeItem.bitCount = translated.length;

							const totalBits = translated.length;
							const nibbleBoundaryBits = Math.ceil(totalBits / 4) * 4;
							const wordBoundaryBits = Math.ceil(totalBits / 16) * 16;
							metadataInfo = `Bits: ${totalBits}, padded to nibble boundary: ${nibbleBoundaryBits}, padded to word boundary: ${wordBoundaryBits}`;
						} else {
							translated = encoder.translate(this.inputString, match.scheme, targetLevel, options);
						}

						schemeItem.levels.push({
							type: targetLevel,
							textContent: targetLevel !== 'BINARY' ? translated : '',
							htmlContent: htmlContent,
							rawValue: translated,
							meta: metadataInfo
						});
					} catch (translationError) {
						console.debug(`Skipping non-matching permutation candidate ${match.scheme} at level ${targetLevel}:`, translationError);
					}
				}

				if (this.inputLevel === 'HEX' && schemeItem.bitCount === 0) {
					const foundBinaryObj = schemeItem.levels.find(l => l.type === 'BINARY');
					if (foundBinaryObj && foundBinaryObj.rawValue) {
						schemeItem.bitCount = foundBinaryObj.rawValue.length;
					}
				}
				
				if (schemeItem.levels.length > 0) {
					structures.push(schemeItem);
				}
			}
			return structures;
		}
	},

	methods: {
		/**
		 * Loads a selected sample string pattern directly into the working input area.
		 * @param {string} key - Target identity identifier (e.g., 'json', 'digitalLink').
		 */
		loadDemo(key) {
			this.inputString = this.demoValues[key];
		},

		/**
		 * Writes a target text string safely into the system clipboard.
		 * Sets up short-term user interface indicator tokens upon success.
		 * @param {string} text - Raw data value intended for capture.
		 * @param {string} key - Combined level identity value tracking active UI state.
		 */
		copyToClipboard(text, key) {
			if (!text) return;
			navigator.clipboard.writeText(text).then(() => {
				this.activeCopiedKey = key;
				setTimeout(() => {
					if (this.activeCopiedKey === key) this.activeCopiedKey = '';
				}, 1500);
			}).catch(err => {
				console.error('Failed to copy text: ', err);
			});
		},

		/**
		 * Deep-links a chosen output translation parameter into a new, separate working instance.
		 * Encodes the entire string payload cleanly to preserve percent-escaped symbols.
		 * @param {string} value - The raw unescaped value string for transfer.
		 */
		useAsNewInput(value) {
			if (!value) return;
			const baseUrl = window.location.origin + window.location.pathname;
			const targetUrl = `${baseUrl}?input=${encodeURIComponent(value)}`;
			window.open(targetUrl, '_blank');
		}
	},

	/**
	 * Component mounting lifecycle initialization handler.
	 * Resolves search queries safely and prepares the underlying translator instance.
	 */
	mounted() {
		const urlParams = new URLSearchParams(window.location.search);
		if (urlParams.has('input')) {
			/**
			 * CRITICAL RESOLUTION FIX:
			 * URLSearchParams.get() natively evaluates and strips away one pass of 
			 * URI percent decoding on entry. Passing the parameter value straight to 
			 * inputString preserves legitimate literal characters (like '%2F') inside 
			 * GS1 elements.
			 */
			this.inputString = urlParams.get('input');
		}

		const translatorInstance = new TDTtranslator();
		this.myTDTencoder = markRaw(translatorInstance);
		
		this.myTDTencoder.initialized.then(() => {
			this.myTDTencoder.processData();
			this.isInitialized = true;
		}).catch(error => {
			console.error('Error initializing library:', error);
		});
	}
}).mount('#app');

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then((registration) => {
        console.log('ServiceWorker registration successful with scope: ', registration.scope);
      })
      .catch((error) => {
        console.log('ServiceWorker registration failed: ', error);
      });
  });
}