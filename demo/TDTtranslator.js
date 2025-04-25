const alphabetURNcode40 = " ABCDEFGHIJKLMNOPQRSTUVWXYZ-.:0123456789";
const alphabetFileSafeURISafeBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const alphabetUpperCaseHexadecimal = "0123456789ABCDEF";
const alphabetLowerCaseHexadecimal = "0123456789abcdef";

const regexBinaryString = /^[01]+$/;
const regexURNcode40 = /^[A-Z0-9\.:-]+$/;
const regexFileSafeURISafeBase64 = /^[A-Za-z0-9_-]+$/;
const regexUpperCaseHexadecimal = /^[0-9A-F]+$/;
const regexLowerCaseHexadecimal = /^[0-9a-f]+$/;
const regexHexadecimal = /^[0-9A-Fa-f]+$/;
const regexAlphanumeric=/^[\x21-\x23\x25-\x5A\x5A-\x7A]+$/;
const regexAllNumeric = /^[0-9]+$/;
const regexEightBit=/^[\x00-\x7F]*$/;
const regexSevenBit=/^[\x20-\x7F]*$/;
const regexSixBit=/^[\x20-\x5F]*$/;
const regexFiveBit=/^[\x40-\x5F]*$/;
const regexDateYYMMDD=/^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)$/;
const regexDateYYMMDDhhmm=/^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)(?:(?:[01][0-9]|2[0-3])(?:[0-5][0-9])|2400)$/;
const regexDateYYMMDDorYYMMDDYYMMDD=/^(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)){1,2}$/;
const regexVariablePrecisionDateTimeYYMMDDhh_mmss=/^[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|30|31)(?:[01][0-9]|2[0-4])?(?:[0-5][0-9])?(?:[0-5][0-9])?$/
const regexCountryCode=/^[A-Z]{2}$/;
const regexAIkey = /^[0-9]{2,4}$/;
const regexAIkeyPrioritisedDate = /^(?:11|13|15|16|17|7006|7007)$/;
const regexOptionalMinus = /^[-]?$/;
const regexSingleBit = /^[01]$/;

const regexRule = /^([A-Z0-9]+)\((.+)\)$/
const regexStatic = /^'(.+)'$/
const regexURIEscapeChar = /^[#/%&+,!()*':;<=>?']$/
const regexURNEscapeChar = /^["#%&()/<>?]$/

const tdtDataContainer = 'tdt:epcTagDataTranslation'

const reverseHash=function(obj) {
	let reversed={};
	let keys=Object.keys(obj);
	for (let i=0; i<keys.length; i++) {
		reversed[obj[keys[i]]]=keys[i];
	}
	return reversed;
}

const fromAItoPrioritisedDateIndicator = {"11":"0000","13":"0001","15":"0010","16":"0011","17":"0100","7006":"0101","7007":"0110"};
const fromPrioritisedDateIndicatorToAI = reverseHash(fromAItoPrioritisedDateIndicator);

const calculateGS1CheckDigit = function(gs1IDValue) {
	if (regexAllNumeric.test(gs1IDValue)) {
		let counter=0;
		let total=0;
		for (let i=gs1IDValue.length-1; i>=0; i--) {
			total+=((gs1IDValue.charAt(i))*(3-2*(counter%2)));
			counter++;
		}
		let expectedCheckDigit=(10-(total%10))%10;
		return expectedCheckDigit;
	} else {
		throw new Error("Cannot calculate a GS1 Check Digit for "+gs1IDValue+" because it is not a numeric string of digits 0-9 only");
	}
}

const matchEncodingIndicator = function(indicator) {
	return function(element) {
		return element.indicator == indicator;
	}
}

/*
 * "Rule" processing
 */
const processRule = function(rule, internalMap, options, checkList) {
    console.debug("Processing rule "+JSON.stringify(rule, null, 2));

    if (internalMap.hasOwnProperty(rule.newFieldName)) return;

    let func = regexRule.exec(rule.function);
    func.shift();
    if (func.length < 2) {
        throw new Error("Failed parsing rule");
    }
    let args = func[1].split(",");

    /*
     *  Find the arguments for the rule function
     *
     *  If the argument is numeric, just push that value
     *  otherwise look for the value relating to that field
     *  in the internalMap
     */
    let argVals = [];
    for (let a of args) {
        if (regexAllNumeric.test(a)) {
            argVals.push(a);
            continue;
        }

        if (a.match(regexStatic)) {
            console.debug(a+" is a static value");
            let vals = regexStatic.exec(a);
            argVals.push(vals[1]);
            continue;
        }

        console.debug("Looking for "+a);
        if (!internalMap.hasOwnProperty(a)) {
            if (rule.type == "EXTRACT" && !checkList.includes(a)) {
                console.debug(a+" not in input - skipping rule");
                return;
            }
            if (rule.type == "FORMAT" && !checkList.includes(rule.newFieldName)) {
                console.debug(rule.newFieldName+" not required - skipping rule");
                return;
            }
            if (!options.hasOwnProperty(a)) {
                throw new Error("Missing argument "+a);
            }
            argVals.push(options[a]);
        } else {
            argVals.push(internalMap[a]);
        }
    }
    console.debug("Rule arguments: "+JSON.stringify(argVals));

    /*
     *  By this point func[0] will be the function name and
     *  argVals will be an array of values to pass to the function
     */
    switch (func[0]) {
        case "URLENCODE": {
            let encoded = '';
            for (let argVal of argVals) {
                for (let i = 0; i < argVal.length; i++) {
                    if (regexURIEscapeChar.test(argVal.charAt(i))) {
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
            internalMap[rule.newFieldName] = calculateGS1CheckDigit(argVals[0]);
            break;
        }
        case "URNENCODE": {
            let encoded = '';
            for (let argVal of argVals) {
                for (let i = 0; i < argVal.length; i++) {
                    if (regexURNEscapeChar.test(argVal.charAt(i))) {
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

/*
 * Pre and Post processing functions
 */

// Re-arrange JSON strings so AIs listed in aiSequence are first
const jsonPreFormat = function(string, aiSequence) {
    let parsed = JSON.parse(string);
    let formatted = '{';

    // First put the required AIs into the string
    for (let ai of aiSequence) {
        if (ai in parsed) {
            formatted += '"' + ai + '":"' + parsed[ai] + '",';
            delete parsed[ai];
        } else {
            return "";
        }
    }

    // Now add any remaining AIs
    for (let ai in parsed) {
        formatted += '"' + ai + '":"' + parsed[ai] + '",';
    }
    formatted = formatted.slice(0, -1) + "}";
    console.debug("Pre-formatted JSON "+formatted)
    return formatted;
}

// Re-arrange Digital Link URI to match the expected AI sequence for regex matches
// This does assume that AIs are in the correct component of the URI
const digitalLinkPreFormat = function(string, aiSequence) {
    let extra = [];
    aiNum = 0;
    const urlRegex = /(https?:\/\/[^/]+)\/([^?]+\??)(.*)/;
    const stemRegex = /([0-9]{2,4})\/([^/?]+)[/?]?(.*)/;
    const optRegex = /([0-9]{2,4})=([^&]+)&?(.*)/;

    let split = urlRegex.exec(string);
    if (split.length < 4) {
        return "";
    }

    let formatted = split[1];
    while (split[2].length > 0) {
        let aiPair = stemRegex.exec(split[2]);
        if (aiPair.length < 4) {
            return "";
        }
        if ((aiNum < aiSequence.length) && aiPair[1] == aiSequence[aiNum]) {
            formatted += '/'+aiPair[1]+'/'+aiPair[2];
            aiNum++;
        } else {
            extra[aiPair[1]] = aiPair[2];
        }
        split[2] = aiPair[3];
    }

    let sep = '?';

    while (split[3].length > 0) {
        let aiPair = optRegex.exec(split[3]);
        if (aiPair.length < 4) {
            return "";
        }
        if ((aiNum < aiSequence.length) && aiPair[1] == aiSequence[aiNum]) {
            formatted += sep+aiPair[1]+'='+aiPair[2];
            aiNum++;
            sep = '&';
        } else {
            extra[aiPair[1]] = aiPair[2];
        }
        split[3] = aiPair[3];
    }

    // Now add any remaining AIs
    for (let ai in extra) {
        formatted += sep + ai + '=' + extra[ai];
        sep = '&';
    }
    console.debug("Pre-formatted URI "+formatted)
    return formatted;
}

// Take a Digital Link URI as created by TDT grammar and re-arrange components
// so that any key qualifier AIs found in the options section are moved to the
// correct place.
const digitalLinkPostFormat = function(string, keyQualifiers) {
    let found = [];
    const urlRegex = /(https?:\/\/[^/]+\/[0-9]{2,4}\/[^/?]+)\/?([^?]*)\??(.*)/;
    const stemRegex = /([0-9]{2,4})\/([^/]+)[/?]?(.*)/;
    const optRegex = /([0-9]{2,4})=([^&]+)&?(.*)/;

    let split = urlRegex.exec(string);
    if (split.length < 4) {
        return "";
    }

    let formatted = split[1]; // This will be the stem and the key identifier

    // Split the remainder of the path into AIs - some components from the options
    // may need to go in amongst this lot
    while (split[2].length > 0) {
        let aiPair = stemRegex.exec(split[2]);
        if (aiPair.length < 4) {
            return "";
        }
        found[aiPair[1]] = aiPair[2];
        split[2] = aiPair[3];
    }

    // Hunt through the options to look for any key qualifiers
    let options = "";
    let sep = "?";
    while (split[3].length > 0) {
        let aiPair = optRegex.exec(split[3]);
        if (aiPair.length < 4) {
            return "";
        }
        if (keyQualifiers.includes(aiPair[1])) {
            found[aiPair[1]] = aiPair[2];
        } else {
            options += sep + aiPair[1]+"="+aiPair[2];
            sep = '&';
        }
        split[3] = aiPair[3];
    }

    // Put the key qualifiers in place
    for (var aiNum = 0; aiNum < keyQualifiers.length; aiNum++) {
        if (keyQualifiers[aiNum] in found) {
            formatted += '/' + keyQualifiers[aiNum] + '/' + found[keyQualifiers[aiNum]];
        }
    }

    formatted += options;

    console.debug("Post-formatted URI "+formatted)
    return formatted;
}

/*
 *  Helper functions for encoders / decoders
 */

const prePad=function(string, padCharacter, finalLength) {
    if (string.length < finalLength) {
        string = padCharacter.repeat(finalLength - string.length) + string;
    }
    return string;
}

const postPad=function(string, padCharacter, finalLength) {
    if (string.length < finalLength) {
        string += padCharacter.repeat(finalLength - string.length);
    }
    return string;
}

const toBinaryUsingTruncatedASCII = function(inputCharacterString, bitsPerChr) {
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

const fromBinaryUsingTruncatedASCII = function(inputBinaryString, bitsPerChr) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
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

        // If we've walked past useful ASCII, decoding is done
        // (typically trailing 0000)
        if (charCode < 32) break;

        outputCharacterString += String.fromCharCode(charCode);
    }

    return outputCharacterString;
}


/*
 *	TDS 2.0 encoder / decoders
 *
 * Encoders take a single component of an AI plus the relevant Table F options
 * as their input and return the encoded binary string.
 *
 * Decoders take a binary string plus the relevant Table F options as their
 * input and return the decoded component plus the number of bits processed.
 * This is because decoding the binary string, where variable length components
 * are involved, cannot be done with a simple pattern match until the "length"
 * part has been decoded.
 * Trailing binary data is ignored as this will likely be the next encoded AI.
 */

 // TDS section 14.5.2
const toBinaryUsingFixedBitLengthInteger = function(inputCharacterString,options) {
	if (inputCharacterString === undefined) {
		throw new Error("input string is undefined");
	}

	if (!regexAllNumeric.test(inputCharacterString)) {
		throw new Error("input " + inputCharacterString + " does not match regex for all-numeric strings");
	}

	const binary = BigInt(inputCharacterString).toString(2);

	if (binary.length > options.fixLenBits) {
	    throw new Error("input " + inputCharacterString + " cannot be encoded within fixed bit count of "+options.fixLenBits+" bits");
	}

	return prePad(binary, "0", options.fixLenBits);
};

const fromBinaryUsingFixedBitLengthInteger = function(inputBinaryString,options) {
	if (inputBinaryString === undefined) {
		throw new Error("input string is undefined");
	}

	if (!regexBinaryString.test(inputBinaryString)) {
		throw new Error("input " + inputBinaryString + " is not binary - only bit 0 or 1 allowed");
	}

	if (inputBinaryString.length < options.fixLenBits) {
		throw new Error("input " + inputBinaryString + " does not match expected length of "+options.fixLenBits+" bits");
	}

	return {
        "decoded": prePad(BigInt('0b' + inputBinaryString.substring(0, options.fixLenBits)).toString(),"0",options.fixLenChrs),
        "used": options.fixLenBits
    };
};


// TDS section 14.5.3
const toBinaryUsingPrioritisedDate = function(inputAIkey, inputYYMMDD) {
	if (regexAIkeyPrioritisedDate.test(inputAIkey)) {
		if (regexDateYYMMDD.test(inputYYMMDD)) {
			return fromAItoPrioritisedDateIndicator[inputAIkey] + toBinaryUsingDateYYMMDD(inputYYMMDD);
		} else {
			throw new Error("Input date " + inputYYMMDD + " does not match regex for a YYMMDD date value");
	    }
	} else {
		throw new Error("Input AI (" + inputAIkey + ") does not match regex for a GS1 Application Identifier that can be used with a prioritised date within DSGTIN+");
	}
}

const fromBinaryUsingPrioritisedDate = function(inputBinaryString) {
	if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
		throw new Error("Input is not binary - only bit 0 or 1 allowed");
	}

	const length = inputBinaryString.length;

	if (length < 20) {
		throw new Error(`Input string must be 20 bits for method fromBinaryUsingPrioritisedDate`);
	}

	const prioritisedDateIndicator = inputBinaryString.substr(0, 4);
	const binaryDateValue = inputBinaryString.substr(4, 16);

	return {
		"AI": fromPrioritisedDateIndicatorToAI[prioritisedDateIndicator],
		"decoded": fromBinaryUsingDateYYMMDD(binaryDateValue),
        "used": 20
	};
}


// TDS section 14.5.4
const toBinaryUsingFixedLengthNumeric = function(inputCharacterString) {
    let outputBinaryString = "";
    for (let t = 0; t < inputCharacterString.length; t++) {
        const value = parseInt(inputCharacterString.charAt(t));
        outputBinaryString += prePad(value.toString(2), "0", 4);
    }
    return outputBinaryString;
}

const fromBinaryUsingFixedLengthNumeric = function(inputBinaryString, options) {
    let outputCharacterString = "";
    if (inputBinaryString.length < options.fixLenBits) {
        throw new Error(`Input string must be `+options.fixLenBits+ 'bits');
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


// TDS section 14.5.5
const toBinaryUsingDelimitedNumeric = function(inputCharacterString, options) {
    let outputBinaryString = "";
    let t = 0;
    for (t = 0; t < inputCharacterString.length; t++) {
        const value = parseInt(inputCharacterString.charAt(t));
        if (isNaN(value)) {
            break;
        } else {
            outputBinaryString += prePad(value.toString(2), "0", 4);
        }
    }
    if (t < inputCharacterString.length) {
        outputBinaryString += "1110";
        outputBinaryString += toBinaryUsingVariableLengthAlphanumeric(inputCharacterString.substr(t), options);
    } else {
        outputBinaryString += "1111";
    }
    return outputBinaryString;
}

const fromBinaryUsingDelimitedNumeric = function(inputBinaryString, options) {
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
            extra = fromBinaryUsingVariableLengthAlphanumeric(inputBinaryString.substr(t), options);
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

/*
 *  Individual encoder / decoders used in 14.5.6
 */

// TDS section 14.5.6.1
const toBinaryUsingBigInteger = function(inputCharacterString) {
    if (inputCharacterString === undefined) {
        throw new Error("input string is undefined");
    }

    if (!regexAllNumeric.test(inputCharacterString)) {
        throw new Error("input " + inputCharacterString + " does not match regex for all-numeric");
    }

    const bitLength = Math.ceil(Math.log2(Math.pow(10, inputCharacterString.length) - 1));
    const binary = BigInt(inputCharacterString).toString(2);

    return prePad(binary, "0", bitLength);
}

const fromBinaryUsingBigInteger = function(inputBinaryString) {
    if (inputBinaryString === undefined) {
        throw new Error("input string is undefined");
    }

    if (!regexBinaryString.test(inputBinaryString)) {
        throw new Error("input " + inputBinaryString + " is not binary - only bit 0 or 1 allowed");
    }

    return BigInt('0b' + inputBinaryString).toString();
}


// TDS section 14.5.6.2
const toBinaryUsingUpperCaseHexadecimal = function(inputCharacterString) {
    if (!regexUpperCaseHexadecimal.test(inputCharacterString)) {
        throw new Error(`Input ${inputCharacterString} does not match regex for upper case hexadecimal`);
    }

    let outputBinaryString = "";
    for (let t = 0; t < inputCharacterString.length; t++) {
        const index = alphabetUpperCaseHexadecimal.indexOf(inputCharacterString.charAt(t));
        const binary = prePad(index.toString(2), "0", 4);
        outputBinaryString += binary;
    }
    return outputBinaryString;
}

const fromBinaryUsingUpperCaseHexadecimal = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
        throw new Error("Input is not binary - only bit 0 or 1 allowed");
    }

    let outputCharacterString = "";
    if (inputBinaryString.length % 4 === 0) {
        for (let t = 0; t < inputBinaryString.length; t += 4) {
            const binarySubstring = inputBinaryString.substr(t, 4);
            const decimal = parseInt(binarySubstring, 2);
            outputCharacterString += alphabetUpperCaseHexadecimal.charAt(decimal);
        }
        return outputCharacterString;
    } else {
        throw new Error("Input is not an exact multiple of 4 bits");
    }
}


// TDS section 14.5.6.3
const toBinaryUsingLowerCaseHexadecimal = function(inputCharacterString) {
    if (!regexLowerCaseHexadecimal.test(inputCharacterString)) {
        throw new Error(`Input ${inputCharacterString} does not match regex for Lower case hexadecimal`);
    }

    let outputBinaryString = "";
    for (let t = 0; t < inputCharacterString.length; t++) {
        const index = alphabetLowerCaseHexadecimal.indexOf(inputCharacterString.charAt(t));
        const binary = prePad(index.toString(2), "0", 4);
        outputBinaryString += binary;
    }
    return outputBinaryString;
}

const fromBinaryUsingLowerCaseHexadecimal = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
        throw new Error("Input is not binary - only bit 0 or 1 allowed");
    }

    let outputCharacterString = "";
    if (inputBinaryString.length % 4 === 0) {
        for (let t = 0; t < inputBinaryString.length; t += 4) {
            const binarySubstring = inputBinaryString.substr(t, 4);
            const decimal = parseInt(binarySubstring, 2);
            outputCharacterString += alphabetLowerCaseHexadecimal.charAt(decimal);
        }
        return outputCharacterString;
    } else {
        throw new Error("Input is not an exact multiple of 4 bits");
    }
}


// TDS section 14.5.6.4
const toBinaryUsingFileSafeURISafeBase64 = function(inputCharacterString) {
    if (!regexFileSafeURISafeBase64.test(inputCharacterString)) {
        throw new Error(`Input ${inputCharacterString} does not match regex for file-safe URI-safe base 64`);
    }

    let outputBinaryString = "";
    for (let t = 0; t < inputCharacterString.length; t++) {
        const index = alphabetFileSafeURISafeBase64.indexOf(inputCharacterString.charAt(t));
        const binary = prePad(index.toString(2), "0", 6);
        outputBinaryString += binary;
    }
    return outputBinaryString;
}

const fromBinaryUsingFileSafeURISafeBase64 = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
        throw new Error("Input is not binary - only bit 0 or 1 allowed");
    }

    let outputCharacterString = "";
    if (inputBinaryString.length % 6 === 0) {
        for (let t = 0; t < inputBinaryString.length; t += 6) {
            const binarySubstring = inputBinaryString.substr(t, 6);
            const decimal = parseInt(binarySubstring, 2);
            outputCharacterString += alphabetFileSafeURISafeBase64.charAt(decimal);
        }
        return outputCharacterString;
    } else {
        throw new Error("Input is not an exact multiple of 6 bits");
    }
}


// TDS section 14.5.6.5
const toBinaryUsingURNcode40 = function(inputCharacterString) {
    let outputBinaryString = "";
    if (regexURNcode40.test(inputCharacterString)) {
        if (inputCharacterString.length % 3 > 0) {
            inputCharacterString += " ".repeat(3 - (inputCharacterString.length % 3));
        }
        for (let t = 0; t < inputCharacterString.length / 3; t++) {
            const i1 = alphabetURNcode40.indexOf(inputCharacterString.charAt(3 * t));
            const i2 = alphabetURNcode40.indexOf(inputCharacterString.charAt(3 * t + 1));
            const i3 = alphabetURNcode40.indexOf(inputCharacterString.charAt(3 * t + 2));
            const b = prePad(((1600 * i1 + 40 * i2 + i3 + 1) >>> 0).toString(2), "0", 16);
            outputBinaryString += b;
        }
        return outputBinaryString;
    } else {
        throw new Error(`Input ${inputCharacterString} does not match regex for URN Code 40`);
    }
}

const fromBinaryUsingURNcode40 = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
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
            outputCharacterString += alphabetURNcode40.charAt(c1) + alphabetURNcode40.charAt(c2) + alphabetURNcode40.charAt(c3);
        }
        outputCharacterString = outputCharacterString.split(" ").join(""); // Remove spaces
        return outputCharacterString;
    } else {
        throw new Error("Input is not an exact multiple of 16 bits");
    }
}


// TDS section 14.5.6.6
const toBinaryUsingSevenBitASCII = function(inputCharacterString) {
	return toBinaryUsingTruncatedASCII(inputCharacterString,7);
}

const fromBinaryUsingSevenBitASCII = function(inputBinaryString) {
	return fromBinaryUsingTruncatedASCII(inputBinaryString,7);
}


// TDS section 14.5.6
const encodingOptionsAlphanumeric=[
	{"regex":regexSevenBit, "indicator": "100","text":"7-bit ASCII","num":7,"denom":1,"encoder": toBinaryUsingSevenBitASCII ,"decoder": fromBinaryUsingSevenBitASCII},
	{"regex":regexFileSafeURISafeBase64, "indicator": "011","text":"file-safe URI-safe base 64","num":6,"denom":1,"encoder": toBinaryUsingFileSafeURISafeBase64,"decoder": fromBinaryUsingFileSafeURISafeBase64},
	{"regex":regexLowerCaseHexadecimal, "indicator": "010","text":"lower case hexadecimal","num":4,"denom":1,"encoder": toBinaryUsingLowerCaseHexadecimal ,"decoder": fromBinaryUsingLowerCaseHexadecimal},
	{"regex":regexUpperCaseHexadecimal, "indicator": "001","text":"upper case hexadecimal","num":4,"denom":1,"encoder": toBinaryUsingUpperCaseHexadecimal ,"decoder": fromBinaryUsingUpperCaseHexadecimal},
	{"regex":regexAllNumeric, "indicator": "000","text":"All-numeric","num":Math.log(10),"denom":Math.log(2),"encoder": toBinaryUsingBigInteger,"decoder": fromBinaryUsingBigInteger},
	{"regex":regexURNcode40, "indicator": "101","text":"URN Code 40","num":16,"denom": 3,"encoder": toBinaryUsingURNcode40,"decoder": fromBinaryUsingURNcode40}
];

const byAscendingBitCount = function(a,b) {
	if (a.bitCount < b.bitCount) { return -1; }
	if (a.bitCount > b.bitCount) { return 1; }
	return a.indicator > b.indicator ? 1 : -1 ; // Not strictly needed, but gives consistent behaviour to help tests.
}

const toBinaryUsingVariableLengthAlphanumeric = function(inputCharacterString, options) {
	let candidates=[];

	const length=inputCharacterString.length;

    for (o of encodingOptionsAlphanumeric) {
		if (o.regex.test(inputCharacterString)) {
			let bitCount=0;
			if (o.denom == 1) {
				bitCount=Math.ceil(length*o.num);
			} else {
				if (o.denom == 3) {
					bitCount=Math.ceil(o.num*Math.ceil(length/o.denom));
				} else {
					bitCount=Math.ceil(o.num*length/o.denom);
				}
			}
			candidates.push({"indicator": o.indicator, "text":o.text, "bitCount":bitCount,"encoder":o.encoder});
		}
	}

	if (candidates.length == 0 ) {
		throw new Error("No viable encoding option found for "+JSON.stringify(inputCharacterString)+" - check for non-encodable characters.");
	}

	let sortedCandidates=candidates.sort(byAscendingBitCount);
	let mostEfficientEncoding=sortedCandidates[0];
    console.debug("Using encoding "+mostEfficientEncoding.text);
	return mostEfficientEncoding.indicator + prePad(length.toString(2), "0", options.lenIndBits) + mostEfficientEncoding.encoder(inputCharacterString);
}

const fromBinaryUsingVariableLengthAlphanumeric = function(inputBinaryString, options) {
	let rv={};
    rv.used = 0;

    if ((inputBinaryString !== undefined) && (regexBinaryString.test(inputBinaryString))) {
		let encodingIndicator=inputBinaryString.substr(0,3);
        rv.used += 3;
		let length=parseInt(inputBinaryString.substr(3,options.lenIndBits),2);
        rv.used += options.lenIndBits;

		let decodingOption = encodingOptionsAlphanumeric.filter(matchEncodingIndicator(encodingIndicator))[0];

		if (decodingOption.denom == 1) {
			bitCount=Math.ceil(length*decodingOption.num);
		} else {
			if (decodingOption.denom == 3) {
				bitCount=Math.ceil(decodingOption.num*Math.ceil(length/decodingOption.denom));
			} else {
				bitCount=Math.ceil(decodingOption.num*length/decodingOption.denom);
			}
		}

        let binaryValue = inputBinaryString.substr(rv.used,bitCount);
        rv.used += bitCount;
        rv.decoded=prePad(decodingOption.decoder(binaryValue), "0", length);
		return rv;

	} else {
    	if (inputBinaryString == undefined) {
 	       throw new Error("input string is undefined");
    	} else {
 	       throw new Error(inputBinaryString+" is not binary - only bit 0 or 1 allowed");
    	}
	}
}


// TDS section 14.5.7
const toBinaryUsingSingleDataBit = function(inputCharacterString) {
    if (!regexSingleBit.test(inputCharacterString)) {
        throw new Error(`Input ${inputCharacterString} does not match regex for a single bit (0 or 1)`);
    }
	return inputCharacterString;
}

const fromBinaryUsingSingleDataBit = function(inputBinaryString) {
    if (!regexSingleBit.test(inputBinaryString.substr(0,1))) {
        throw new Error(`Input ${inputBinaryString} does not match regex for a single bit (0 or 1)`);
    }
	return {
        "decoded": inputBinaryString.substr(0, 1),
        "used": 1
    };
}


// TDS section 14.5.8
const toBinaryUsingDateYYMMDD = function(inputYYMMDD) {
    if (!regexDateYYMMDD.test(inputYYMMDD)) {
        throw new Error(`Input ${inputYYMMDD} does not match regex for date YYMMDD`);
    }

    const yy = parseInt(inputYYMMDD.substr(0, 2)).toString(2).padStart(7, "0");
    const mm = parseInt(inputYYMMDD.substr(2, 2)).toString(2).padStart(4, "0");
    const dd = parseInt(inputYYMMDD.substr(4, 2)).toString(2).padStart(5, "0");

    return yy + mm + dd;
}

const fromBinaryUsingDateYYMMDD = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
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


// TDS section 14.5.9
const toBinaryUsingDateYYMMDDhhmm = function(inputYYMMDDhhmm) {
    if (!regexDateYYMMDDhhmm.test(inputYYMMDDhhmm)) {
        throw new Error(`Input ${inputYYMMDDhhmm} does not match regex for date YYMMDDhhmm`);
    }

    const yy = parseInt(inputYYMMDDhhmm.substr(0, 2)).toString(2).padStart(7, "0");
    const mm = parseInt(inputYYMMDDhhmm.substr(2, 2)).toString(2).padStart(4, "0");
    const dd = parseInt(inputYYMMDDhhmm.substr(4, 2)).toString(2).padStart(5, "0");
    const hh = parseInt(inputYYMMDDhhmm.substr(6, 2)).toString(2).padStart(5, "0");
    const nn = parseInt(inputYYMMDDhhmm.substr(8, 2)).toString(2).padStart(6, "0");

    return yy + mm + dd + hh + nn;
}

const fromBinaryUsingDateYYMMDDhhmm = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
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


// TDS section 14.5.10
const toBinaryUsingDateOrDateRange = function(inputYYMMDDorYYMMDDYYMMDD) {
    if (inputYYMMDDorYYMMDDYYMMDD === undefined) {
        throw new Error("input string is undefined");
    }

    if (!regexDateYYMMDDorYYMMDDYYMMDD.test(inputYYMMDDorYYMMDDYYMMDD)) {
        throw new Error("input " + inputYYMMDDorYYMMDDYYMMDD + " does not match regex for date YYMMDD or date range YYMMDDYYMMDD");
    }

    const y1 = inputYYMMDDorYYMMDDYYMMDD.substr(0, 2);
    const m1 = inputYYMMDDorYYMMDDYYMMDD.substr(2, 2);
    const d1 = inputYYMMDDorYYMMDDYYMMDD.substr(4, 2);
    if (inputYYMMDDorYYMMDDYYMMDD.length === 6) {
        return "0" + prePad(parseInt(y1).toString(2), "0", 7) + prePad(parseInt(m1).toString(2), "0", 4) + prePad(parseInt(d1).toString(2), "0", 5);
    } else {
        const y2 = inputYYMMDDorYYMMDDYYMMDD.substr(6, 2);
        const m2 = inputYYMMDDorYYMMDDYYMMDD.substr(8, 2);
        const d2 = inputYYMMDDorYYMMDDYYMMDD.substr(10, 2);
        return "1" + prePad(parseInt(y1).toString(2), "0", 7) + prePad(parseInt(m1).toString(2), "0", 4) + prePad(parseInt(d1).toString(2), "0", 5) + prePad(parseInt(y2).toString(2), "0", 7) + prePad(parseInt(m2).toString(2), "0", 4) + prePad(parseInt(d2).toString(2), "0", 5);
    }
}


const fromBinaryUsingDateOrDateRange = function(inputBinaryString) {
    if (inputBinaryString === undefined) {
        throw new Error("input string is undefined");
    }

    if (!regexBinaryString.test(inputBinaryString)) {
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

    let result = prePad(yy1.toString(), "0", 2) + prePad(mm1.toString(), "0", 2) + prePad(dd1.toString(), "0", 2);

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
            throw new Error("input string must not encode a DD day value < 1; end DD value in date range = " + dd2);
        }

        result += prePad(yy2.toString(), "0", 2) + prePad(mm2.toString(), "0", 2) + prePad(dd2.toString(), "0", 2);
    }

    return {
        "decoded": result,
        "used": (isDateRange ? 33 : 17)
    };
}


// TDS section 14.5.11
const toBinaryUsingVariablePrecisionDateTime = function(inputYYMMDDhh_mmss) {
    if (!regexVariablePrecisionDateTimeYYMMDDhh_mmss.test(inputYYMMDDhh_mmss)) {
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

const fromBinaryUsingVariablePrecisionDateTime = function(inputBinaryString) {
    if (!inputBinaryString || !regexBinaryString.test(inputBinaryString)) {
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
            throw new Error(`Input string must not encode a ss second value > 59; ${ss} found`);
        }
        outputStrings.push(`${ss.toString().padStart(2, "0")}`);
        used += 6;
    }

    return {
        "decoded": outputStrings.join(""),
        "used": used
    };
}


// TDS section 14.5.12
const toBinaryUsingCountryCode = function(inputCountryCode) {
    if (inputCountryCode === undefined) {
        throw new Error("input string is undefined");
    }
    // do regex check on inputCharacterString to check that it can be encoded
    inputCountryCode = inputCountryCode.toUpperCase();
    if (regexCountryCode.test(inputCountryCode)) {
        return toBinaryUsingFileSafeURISafeBase64(inputCountryCode);
    } else {
        throw new Error("input " + inputCountryCode + " does not match regex for country code");
    }
}

const fromBinaryUsingCountryCode = function(inputBinaryString) {
    if (inputBinaryString === undefined) {
        throw new Error("input string is undefined");
    }

    if (!regexBinaryString.test(inputBinaryString)) {
        throw new Error(inputBinaryString + " is not binary - only bit 0 or 1 allowed");
    }

    if (inputBinaryString.length < 12) {
        throw new Error("input string must be 12 bits for method fromBinaryUsingCountryCode");
    }

    return {
        "decoded": fromBinaryUsingFileSafeURISafeBase64(inputBinaryString.substr(0, 12)),
        "used": 12
    };
}


// TDS section 14.5.13
const toBinaryUsingVariableLengthNumeric = function(inputCharacterString, options) {
	return prePad(inputCharacterString.length.toString(2), "0", options.lenIndBits) + toBinaryUsingBigInteger(inputCharacterString);
}

const fromBinaryUsingVariableLengthNumeric = function(inputBinaryString, options) {
    let length = parseInt(inputBinaryString.substr(0, options.lenIndBits), 2);
    const bitLength = Math.ceil(Math.log2(Math.pow(10, length) - 1));
    return {
        "decoded": prePad(fromBinaryUsingBigInteger(inputBinaryString.substr(options.lenIndBits, bitLength)), "0", length),
        "used": options.lenIndBits + bitLength
    };
};

// TDS section 14.5.14
const toBinaryUsingOptionalMinus = function(inputCharacterString) {
    if (!regexOptionalMinus.test(inputCharacterString)) {
        throw new Error(`Input ${inputCharacterString} does not match regex for optional minus ('-' or empty string)`);
    }
    return (inputCharacterString == "-") ? "1" : "0";
}

const fromBinaryUsingOptionalMinus = function(inputBinaryString) {
    if (!regexSingleBit.test(inputBinaryString.charAt(0))) {
        throw new Error(`Input ${inputBinaryString} does not match regex for a single bit (0 or 1)`);
    }
   	return {
        "decoded": (inputBinaryString.charAt(0) == "1")? "-" : "",
        "used": 1
    };
}



const tds2encodingMethods={
    "14.5.2": { "regex": regexAllNumeric, "encoder": toBinaryUsingFixedBitLengthInteger, "decoder": fromBinaryUsingFixedBitLengthInteger },
    "14.5.3": {}, // Only used for DSGTIN+ date option
    "14.5.4": { "regex": regexAllNumeric, "encoder": toBinaryUsingFixedLengthNumeric, "decoder": fromBinaryUsingFixedLengthNumeric },
    "14.5.5": { "regex": regexAlphanumeric, "encoder": toBinaryUsingDelimitedNumeric, "decoder": fromBinaryUsingDelimitedNumeric },
    "14.5.6": { "regex": regexAlphanumeric, "encoder": toBinaryUsingVariableLengthAlphanumeric, "decoder": fromBinaryUsingVariableLengthAlphanumeric },
    "14.5.7": { "regex": regexSingleBit, "encoder": toBinaryUsingSingleDataBit, "decoder": fromBinaryUsingSingleDataBit },
    "14.5.8": { "regex": regexDateYYMMDD, "encoder": toBinaryUsingDateYYMMDD, "decoder": fromBinaryUsingDateYYMMDD },
    "14.5.9": { "regex": regexDateYYMMDDhhmm, "encoder": toBinaryUsingDateYYMMDDhhmm, "decoder": fromBinaryUsingDateYYMMDDhhmm },
    "14.5.10": { "regex": regexDateYYMMDDorYYMMDDYYMMDD, "encoder": toBinaryUsingDateOrDateRange, "decoder": fromBinaryUsingDateOrDateRange },
    "14.5.11": { "regex": regexVariablePrecisionDateTimeYYMMDDhh_mmss, "encoder": toBinaryUsingVariablePrecisionDateTime, "decoder": fromBinaryUsingVariablePrecisionDateTime},
    "14.5.12": { "regex": regexCountryCode, "encoder": toBinaryUsingCountryCode, "decoder": fromBinaryUsingCountryCode },
    "14.5.13": { "regex": regexAllNumeric, "encoder": toBinaryUsingVariableLengthNumeric, "decoder": fromBinaryUsingVariableLengthNumeric },
    "14.5.14": { "regex": regexOptionalMinus, "encoder": toBinaryUsingOptionalMinus, "decoder": fromBinaryUsingOptionalMinus }
};


const toBinaryUsingTableF = function(inputCharacterString, options) {
	const rv={};
	if ((!isNaN(options.maxChars)) && (inputCharacterString.length > options.maxChars) ) {
        throw new Error("inputCharacterString '"+inputCharacterString+"' is longer than specified inputMaxLength ("+options.maxChars+")");
	}
	if ((!isNaN(options.fixLenChrs)) && (inputCharacterString.length != options.fixLenChrs)) {
        throw new Error("inputCharacterString '"+inputCharacterString+"' is not the specified length ("+options.fixLenChrs+")");
    }
    if (!tds2encodingMethods[options.section]) {
        throw new Error("Encoding method not found for TDS section "+options.section);
	} else {
		rv.encodingMethod = tds2encodingMethods[options.section];

        if (!rv.encodingMethod.regex.test(inputCharacterString)) {
			throw new Error("inputCharacterString '"+inputCharacterString+"' does not match required ")
		}

        rv.binary = rv.encodingMethod.encoder(inputCharacterString, options);
		return rv;
	}
};

const fromBinaryUsingTableF = function(inputBinaryString, options) {
	const rv={};

	if (!tds2encodingMethods[options.section]) {
        throw new Error("Encoding method not found for "+JSON.stringify(method));
	} else {
		rv.encodingMethod = tds2encodingMethods[options.section];
		dec = rv.encodingMethod.decoder(inputBinaryString, options);
        rv.characterString = dec.decoded;
        rv.used = dec.used;
		if (!rv.encodingMethod.regex.test(rv.characterString)) {
			console.error("decoded binary did not match regex");
		}

		return rv;
	}
};




class TDTtranslator {

    constructor() {

        this.tdtData = {};
        this.gcpLengths = {};
        this.initialized = this.#fetchAllData(); // Initialize the library

    }

    static #fromJSONExtractPlusData(inputJSONString, aiSequence) {
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

    static #fromBINARYExtractPlusData(inputBinaryString, tablef, tablek) {
        let plusData = [];

        if (inputBinaryString.length < 8) {
            return plusData;
        }
        while (inputBinaryString.length > 8) {
            let ai = parseInt(inputBinaryString.substr(0, 4), 2).toString();
            ai += parseInt(inputBinaryString.substr(4, 4), 2).toString();
            if (!/^[0-9]{2}$/.test(ai)) {
                throw new Error("Invalid decoded AI "+ai);
            }
            inputBinaryString = inputBinaryString.substr(8);

            if (ai == "00" && inputBinaryString.length < 72) return plusData;

            let tableKrow = tablek[ai];
            if (!tableKrow) {
                throw new Error("Invalid AI prefix decoded "+ai);
            }
            if (tableKrow.b > 2) {
                ai += parseInt(inputBinaryString.substr(0, 4), 2).toString();
                if (!/^[0-9]{3}$/.test(ai)) {
                    throw new Error("Invalid decoded AI "+ai);
                }
                inputBinaryString = inputBinaryString.substr(4);
                if (tableKrow.b > 3) {
                    ai += parseInt(inputBinaryString.substr(0, 4), 2).toString();
                    if (!/^[0-9]{4}$/.test(ai)) {
                        throw new Error("Invalid decoded AI "+ai);
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

    static #fromDigitalLinkExtractPlusData(inputDLString) {
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

    static #toBINARYEncodePlusData(plusdata, tablef, returnArray) {
        let rv = [];
        let rvComponents = [];
        for (let data of plusdata) {
            let tableFrow = tablef[data.ai];
            if (tableFrow) {
                console.debug("TableF row for AI ("+data.ai+"): "+JSON.stringify(tableFrow,null,2));

                // Add encoded AI to ouptput
                let aiBin = []
                for (let t = 0; t < data.ai.length; t++) {
                    aiBin.push(prePad(parseInt(data.ai.charAt(t)).toString(2), "0", 4))
                }
                rv.push(aiBin.join(""));
                rvComponents.push("AI " + data.ai + " identifier");

                let plusDataOutput=[];
                let componentCount=1;
                console.debug("Using method "+tableFrow.b+" for encoding component "+componentCount+" as defined in TDS section "+tableFrow.c);

                let componentValue = data.value;
                if (tableFrow.j) {
                    componentValue = componentValue.substr(0, tableFrow.d)
                }
                let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });

                plusDataOutput.push(b.binary);

                if (tableFrow.j) {
                    componentCount ++;
                    componentValue = data.value.substr(tableFrow.d);
                    console.debug("Using method "+tableFrow.i+" for encoding component "+componentCount+" as defined in TDS section "+tableFrow.j);
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

    static #toJSONEncodePlusData(plusdata) {
        let encoded = "";
        for (let data of plusdata) {
            encoded += ',"' + data.ai + '":';
            let json = JSON.stringify(data.value);
            encoded += json;
        }
        return encoded;
    }

    static #toDigitalLinkEncodePlusData(plusdata) {
        let encoded = [];
        for (let data of plusdata) {
            encoded.push (data.ai + "=" + encodeURIComponent(data.value));
        }
        return encoded.join("&");
    }

    #fetchAllData() {
        const promises = [
            this.#fetchZipData('./TDT_JSON_artefacts.zip'),
//            this.#fetchPrefixLengthData('https://www.gs1.org/docs/gcp_length/gcpprefixformatlist.json')
            this.#fetchPrefixLengthData('./gcpprefixformatlist.json')
        ];

        return Promise.all(promises)
            .then(([loadedData]) => {
                // Process the fetched data
				let key="manifest.json";
				let manifestData=unwrapDataByFilename(loadedData,"manifest.json");

                this.tdtData.table={};
				this.tdtData.scheme={};

				for (let table of manifestData.tables) {
                    console.debug(JSON.stringify(table));
                    this.tdtData.table[table.table]=unwrapDataRowsByFilename(loadedData,table.file);
				}

				for (let scheme of manifestData.definitionFiles) {
                    console.debug(JSON.stringify(scheme));
				    this.tdtData.scheme[scheme.scheme]=unwrapDataByFilename(loadedData,scheme.file);
				}

            })
            .catch(error => {
                // Handle errors
                console.error('Error fetching data:', error);
                throw error;
            });
    }

    #fetchZipData(url) {
        return fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to fetch data from ${url}`);
                }
                return response.blob();
            })
            .then(blob => {
                return JSZip.loadAsync(blob);
            })
            .then(function (zip) {
			    // Assuming JSON files are inside the zip, you can extract them here
                const promises = [];
                zip.forEach((relativePath, zipEntry) => {
                    if (!(relativePath.startsWith('__MACOS')) && (relativePath.endsWith('.json'))) {
						let localPart=relativePath.replace(/^.+?\//,"");
						let relativePathWithoutSuffix = localPart.replace(/\.json$/,"");
                   		console.debug('Parsing '+relativePath);
                        promises.push(
                        	zipEntry.async('text').then(
                        		function parseJson(jsonString) {
								    return {"id":relativePathWithoutSuffix,"file":localPart,"data": JSON.parse(jsonString)};
								}
							)
                        );
                    }
                });
                return Promise.all(promises);
            })
            .catch(error => {
                // Handle errors
                console.error(`Error fetching zip data from ${url}:`, error);
                throw error;
            });
    }

    #fetchPrefixLengthData(url) {
        return fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to fetch fata from ${url}`);
                }
                return response.json();
            })
            .then(data => {
                for (let index in data.GCPPrefixFormatList.entry) {
                    let entry = data.GCPPrefixFormatList.entry[index];
                    this.gcpLengths[entry.prefix] = entry.gcpLength;
                }
                console.debug("GCP Length data loaded");
            })
    }

    #lookupPrefixLength(string) {
        let prefix = string.substr(0, 11);
        while (prefix.length > 0) {
            if (prefix in this.gcpLengths) return this.gcpLengths[prefix];
            prefix = prefix.slice(0, -1);
        }
        return -1;
    }

    // Functions within the library that depend on the fetched data
    processData() {
        // Check if data is available
        if (this.tdtData) {
            // Process the data
			console.info("TDT data loaded");
			console.info("supported schemes = "+JSON.stringify(Object.keys(this.tdtData.scheme),null,2));
			console.info("data tables loaded = "+JSON.stringify(Object.keys(this.tdtData.table),null,2));
        } else {
            // Data not available yet, handle accordingly
            console.error('Data not available yet. Please wait for initialization.');
        }
    }

    // Attempt to detect what schemes are represented by a given input string
    autodetect(inputString) {
        if (!this.tdtData) {
             // Data not available yet, handle accordingly
             console.error('Data not available yet. Please wait for initialization.');
             return;
        }

        let rv=[]
        let isHex = false;
        if (regexHexadecimal.test(inputString) && !regexBinaryString.test(inputString)) {
            console.debug("Detected hex input");
            inputString = this.hex2bin(inputString);
            isHex = true;
        }
        for (let s of Object.keys(this.tdtData.scheme)) {
            let optionKey = this.tdtData.scheme[s][tdtDataContainer].scheme.optionKey
            let levels = [];
            for (let level of this.tdtData.scheme[s][tdtDataContainer].scheme.level) {
                levels.push(level.type);
            }
            for (let sl of this.tdtData.scheme[s][tdtDataContainer].scheme.level) {
                if (inputString.startsWith(sl.prefixMatch)) {
                    let testString = inputString;
                    for (let o of sl.option) {
                        switch (sl.type) {
                            case "GS1_AI_JSON": {
                                testString = jsonPreFormat(inputString, o.aiSequence);
                                break;
                            }
                            case "GS1_DIGITAL_LINK": {
                                testString = digitalLinkPreFormat(inputString, o.aiSequence);
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
                                    if (o.field[0].hasOwnProperty('gcpOffset')) {
                                        fields[1] = fields[1].substring(o.field[0].gcpOffset);
                                    } else {
                                        if (["gtin", "itip", "sscc" ].includes(o.field[0].name)) {
                                            fields[1] = fields[1].substring(1);
                                        }
                                    }
                                    prefixLen = this.#lookupPrefixLength(fields[1]);
                                    break;
                                }
                                case "BINARY":
                                case "TAG_ENCODING":
                                case "PURE_IDENTITY": {
                                    if (optionKey == "gs1companyprefixlength") prefixLen = parseInt(o.optionKey);
                                    break;
                                }
                            }
                            rv.push({"scheme":s,"level":(isHex && (sl.type == "BINARY") ? "HEX" : sl.type),"optionKey": {"property": optionKey, "value": o.optionKey}, "supportedLevels": levels, "detectedGCPLength": prefixLen});
                        }
                    }
                }
            }
        }
        return rv;
    }

    // Translate an input string to a output level of a scheme, using scheme specific options
    translate(inputString,scheme,outputLevel,options = {}) {
        // Check if data is available
        let internalMap={};
        let outputLevelData=null;
        let hexOut = false;

        if (!this.tdtData) {
            // Data not available yet, handle accordingly
            console.error('Data not available yet. Please wait for initialization.');
            return;
        }

		console.debug("Request to translate "+inputString+" to "+outputLevel+" using options "+JSON.stringify(options));

        if (!this.tdtData.scheme.hasOwnProperty(scheme)) {
            console.error("Un-supported EPC scheme "+scheme);
            return;
        }

        // If the input is all hex, switch it to binary
        if (regexHexadecimal.test(inputString) && !regexBinaryString.test(inputString)) inputString = this.hex2bin(inputString);

        let optionKey = this.tdtData.scheme[scheme][tdtDataContainer].scheme.optionKey;

        // If we want HEX, then work is done as binary and we convert at the end
        if (outputLevel == 'HEX') {
            hexOut = true;
            outputLevel = 'BINARY';
        }

		console.debug("Auto-detecting input level");
        let foundMatch = false;
		for (let level of this.tdtData.scheme[scheme][tdtDataContainer].scheme.level) {
			if (level.type==outputLevel) {
				console.debug("Found the output level");
				outputLevelData = level;
			}
			console.debug("Checking against "+level.type+" prefixMatch = "+level.prefixMatch);
			if (inputString.startsWith(level.prefixMatch)) {
				console.debug("input appears to match "+level.type);
                let testString = inputString;
                let expectedSources = [];
				for (let option of level.option) {
                    if (!option.pattern) continue;
                    if (optionKey && options.hasOwnProperty(optionKey) && (options[optionKey] != option.optionKey)) {
                        console.debug("Provided option key "+ options[optionKey] + " does not match " + option.optionKey);
                        continue;
                    }

                    console.debug("optionKey = "+option.optionKey+", pattern = "+option.pattern);

                    let pattern_suffix = "";
                    let matchGroups = [];
                    let lastSeq = 0;
                    switch (level.type) {
                        case "BINARY": {
                            // Add a suffix to the pattern to capture encodedAI and any +AIDC data
                            if (option.grammar.includes("encodedAI")) pattern_suffix = '([01]+)';
                            break;
                        }
                        case "GS1_DIGITAL_LINK": {
                            // Add a suffix to the pattern to capture any +AIDC data
                            pattern_suffix = '(.*)';
                            testString = digitalLinkPreFormat(inputString, option.aiSequence);
                            break;
                        }
                        case "GS1_AI_JSON": {
                            testString = jsonPreFormat(inputString, option.aiSequence);
                            break;
                        }
                    }

                    let re=new RegExp(option.pattern+pattern_suffix);

                    if (!re.test(testString)) {
                        console.debug("Input "+inputString+" doesn't match pattern "+option.pattern);
                        continue;
                    }

					console.debug("inputString matches the pattern for this option");
					matchGroups = testString.match(re);
					for (let field of option.field) {
						console.debug("field.name = "+field.name+", matched value = "+matchGroups[field.seq]);
                        if (field.hasOwnProperty("encoding") && (field.encoding == "dateYYMMDD")) {
                            switch (level.type) {
                                case "BINARY": {
                                    internalMap[field.name]=fromBinaryUsingDateYYMMDD(matchGroups[field.seq]).decoded;
                                    break;
                                }
                                default: {
                                    internalMap[field.name]=matchGroups[field.seq];
                                    break;
                                }
                            }
                        } else if (field.hasOwnProperty("compaction")) {
                            if (/[0-9]-bit/.test(field.compaction)) {
                                internalMap[field.name]=fromBinaryUsingTruncatedASCII(matchGroups[field.seq], parseInt(field.compaction))
                            } else {
                                throw new Error("Unknown compaction "+field.compaction);
                            }
                        } else if ((level.type == "BINARY") && (field.hasOwnProperty("decimalMinimum"))) {
                            let value = parseInt(matchGroups[field.seq], 2).toString();
                            // Sane way to set length
                            if (field.hasOwnProperty("length")) {
                                internalMap[field.name] = prePad(value, "0", field.length);
                            } else {
                                // Official insane method - find equivalent field in TAG_ENCODING level and check it's padChar
                                let found = false;
                                for (let testlevel of this.tdtData.scheme[scheme][tdtDataContainer].scheme.level) {
                                    if (testlevel.type != "TAG_ENCODING") continue;
                                    for (let testoption of testlevel.option) {
                                        if (testoption.optionKey != option.optionKey) continue;
                                        for (let testfield of testoption.field) {
                                            if (testfield.name != field.name) continue;
                                            if (testfield.hasOwnProperty("padChar")) {
                                                if (testfield.padDir == "LEFT") {
                                                    value = prePad(value, testfield.padChar, testfield.length);
                                                } else {
                                                    value = postPad(value, testfield.padChar, testfield.length)
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
        					internalMap[field.name]=matchGroups[field.seq];
                        }
                        if (field.seq > lastSeq) lastSeq = field.seq;
                        expectedSources.push(field.name);
    				}
					internalMap["optionKey"]=option.optionKey;
                    if (optionKey) internalMap[optionKey]=option.optionKey;

                    switch (level.type) {
                        case "BINARY": {
                            if (!option.hasOwnProperty("encodedAI")) break;

                            let encodedAIData = matchGroups[lastSeq+1];
                                console.debug("Decoding AIs from "+encodedAIData);
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
                                internalMap["plusdata"]=TDTtranslator.#fromBINARYExtractPlusData(encodedAIData, this.tdtData.table.F, this.tdtData.table.K);
                                break;
                            }

                            case "GS1_AI_JSON": {
                                internalMap["plusdata"]=TDTtranslator.#fromJSONExtractPlusData(testString, option.aiSequence);
                                break;
                            }

                            case "GS1_DIGITAL_LINK": {
                                internalMap["plusdata"]=TDTtranslator.#fromDigitalLinkExtractPlusData(matchGroups[matchGroups.length - 1]);
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

    			// now need to consider any rules defined for this level
	    		if (level.hasOwnProperty("rule")) {
					console.debug("Need to process the rules of type='EXTRACT'");
                    for (const rule of level.rule) {
                        if (rule.type != "EXTRACT") {
                            continue;
                        }
                        processRule(rule, internalMap, options, expectedSources);
                    }
    			}
            }
		}

        if (!foundMatch) {
            console.error("No matches found for input pattern");
            return;
        }

        if (internalMap.hasOwnProperty("plusdata")) {
            options.dataToggle = internalMap.plusdata.length > 0 ? 1 : 0;
        } else {
            options.dataToggle = 0;
        }

        if (!outputLevelData) {
            console.error("Requested output level "+outputLevel+" not found");
            return;
        }

		let finalOutputArray=[];
        let outputArrayEntries=[];
		console.debug("Requested output level "+outputLevel+" found");
        if (outputLevelData.hasOwnProperty("requiredFormattingParameters")) {
			console.debug("Required formatting parameters = "+JSON.stringify(outputLevelData.requiredFormattingParameters));
    		let requiredFormattingParameters = outputLevelData.requiredFormattingParameters.split(",");
			for (let param of requiredFormattingParameters) {
    			if (options.hasOwnProperty(param)) {
		    		console.debug("Specified value for "+param+" of "+options[param]);
				} else {
                    // tagLength appears in requiredFormattingParameters - for choosing between, say SGTIN-96 and SGTIN-198
                    if (param != "tagLength") console.error("Missing value for "+param+" which is required for output at level "+outputLevel+" in scheme "+scheme);
			    }
            }
		}

		console.debug("internalMap : "+JSON.stringify(internalMap,null,2));

        if (!internalMap.hasOwnProperty("optionKey")) {
            console.error("No output option identified");
            return;
        }

        let outputOption = outputLevelData.option.filter(byOptionKey(internalMap.optionKey))[0];
		console.debug("outputOption = "+JSON.stringify(outputOption, null, 2)) ;

        if (outputLevelData.hasOwnProperty("rule")) {
            let outputComponents = outputOption.grammar.match(/('.*?'|[^'\s]+)(?=\s|\s*$)/g);
            console.debug("Processing FORMAT rules");
            for (const rule of outputLevelData.rule) {
                if (rule.type != "FORMAT") continue;
                processRule(rule, internalMap, options, outputComponents);
            }
        }

        let binaryEncodedAI=[];
        let encodedAIs=[];
		if (outputOption.hasOwnProperty("encodedAI")) {
			for (let encodedAIcomponent of outputOption.encodedAI) {
                if (!encodedAIcomponent.hasOwnProperty("ai")) continue;

                let tableFrow = this.tdtData.table.F[encodedAIcomponent.ai];
    			if (tableFrow) {
					console.debug("TableF row for AI ("+encodedAIcomponent.ai+"): "+JSON.stringify(tableFrow,null,2));

					let aiValue = internalMap[encodedAIcomponent.name];
					let encodedAIDataOutput=[];

					let componentCount=1;
					console.debug("Using method "+tableFrow.b+" for encoding component "+componentCount+" as defined in TDS section "+tableFrow.c);

                    let componentValue = aiValue;
                        if (tableFrow.j) {
                        componentValue = componentValue.substr(0, tableFrow.d)
                    }
                    let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.c, "fixLenChrs" : parseInt(tableFrow.d), "fixLenBits": parseInt(tableFrow.e), "encIndBits": parseInt(tableFrow.f), "lenIndBits": parseInt(tableFrow.g), "maxChars": parseInt(tableFrow.h) });
					encodedAIDataOutput.push(b.binary);

                    if (tableFrow.j) {
                        componentCount ++;
                        componentValue = aiValue.substr(tableFrow.d);
                        console.debug("Using method "+tableFrow.i+" for encoding component "+componentCount+" as defined in TDS section "+tableFrow.j);
                        let b = TDTtranslator.toBinaryUsingTableF(componentValue, { "section": tableFrow.j, "fixLenChrs" : parseInt(tableFrow.k), "fixLenBits": parseInt(tableFrow.l), "encIndBits": parseInt(tableFrow.m), "lenIndBits": parseInt(tableFrow.n), "maxChars": parseInt(tableFrow.o) });
                        encodedAIDataOutput.push(b.binary);
					}

					binaryEncodedAI.push(encodedAIDataOutput.join(""));
                    encodedAIs.push(encodedAIcomponent.ai);
				}
			}
            console.debug("binaryEncodedAI = "+JSON.stringify(binaryEncodedAI));
		}

		for (let grammarComponent of outputOption.grammar.match(/('.*?'|[^'\s]+)(?=\s|\s*$)/g)) {
			console.debug("grammarComponent = "+grammarComponent);
			if (/^'(.+?)'$/.test(grammarComponent)) {
				console.debug(grammarComponent+" is literal");
				finalOutputArray.push(grammarComponent.replace(/^'/,"").replace(/'$/,""));
                outputArrayEntries.push('literal')
			}
			if (/^[a-zA-Z][a-zA-Z0-9_]*$/.test(grammarComponent)) {
				console.debug("Non-literal grammar component : "+grammarComponent);

                switch (grammarComponent) {
                    case "dataToggle": {
                        console.debug("Append the dataToggle value of "+options['dataToggle']);
                        if (/^[01]$/.test(options['dataToggle'])) {
                            finalOutputArray.push(options['dataToggle'].toString());
                            outputArrayEntries.push('dataToggle');
                        } else {
                            console.error(options['dataToggle']+" must be 0 or 1");
                        }
                        continue;
                    }

                    case "filter": {
                        let filter = options["filter"];
                        if (internalMap.hasOwnProperty("filter")) {
                            filter = internalMap["filter"]
                        }
                        console.debug("Append the filter value of "+filter);
                        if (outputLevel == "BINARY") {
                            let bitLength = 3;
                            for (let field of outputOption.field) {
                                if (field.name == 'filter') {
                                    bitLength = field.bitLength;
                                }
                            }
                            finalOutputArray.push(TDTtranslator.prePad(parseInt(filter).toString(2),"0",bitLength));
                        } else {
                            finalOutputArray.push(filter);
                        }
                        outputArrayEntries.push('filter');
                        continue;
                    }

                    case "encodedAI": {
                        console.debug("Append the concatenation of binaryEncodedAI "+JSON.stringify(binaryEncodedAI));
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
                            console.debug("Match found in options for "+grammarComponent);
                            finalOutputArray.push(options[grammarComponent]);
                            outputArrayEntries.push(grammarComponent);
                            continue
                        }

                        if (outputOption.hasOwnProperty("field")) {
                            let found = false;
                            for (let f of outputOption.field) {
                                if ((f.name == grammarComponent) && (internalMap.hasOwnProperty(f.name))) {
                                    console.debug("Match found for field "+JSON.stringify(f));
                                    if (f.hasOwnProperty("encoding") && (f.encoding == "dateYYMMDD")) {
                                        switch (outputLevel) {
                                            case "BINARY": {
                                                finalOutputArray.push(toBinaryUsingDateYYMMDD(internalMap[f.name]));
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
                                                    let binary = toBinaryUsingTruncatedASCII(internalMap[f.name], parseInt(f.compaction));
                                                    if (f.hasOwnProperty("bitLength")) {
                                                        if (f.bitPadDir == "LEFT") {
                                                            binary = prePad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                        } else {
                                                            binary = postPad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                        }
                                                    }
                                                    finalOutputArray.push(binary);
                                                } else {
                                                    throw new Error("Unknown compaction "+field.compaction);
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
                                                if (binary == "NaN") binary = ''; // Very odd edge cases such as GDTI-96 with gcpLenght 12
                                                if (f.hasOwnProperty("bitLength")) {
                                                    if (f.bitPadDir == "LEFT") {
                                                        binary = prePad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                    } else {
                                                        binary = postPad(binary, f.padChar ? f.padChar : "0", f.bitLength);
                                                    }
                                                }
                                                finalOutputArray.push(binary)
                                                break;
                                            }
                                            default: {
                                                let value = internalMap[f.name];
                                                if (f.hasOwnProperty("length")) {
                                                    if (f.padDir == "LEFT") {
                                                        value = prePad(value, f.padChar, f.length);
                                                    } else {
                                                        value = postPad(value, f.padChar, f.length);
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

        // If we have +AIDC data, and the output level supports it, add it to the output
        if (internalMap.hasOwnProperty("plusdata") && (internalMap.plusdata.length > 0)) {
            switch(outputLevel) {
                case "BINARY": {
                    if (outputOption.grammar.includes("dataToggle")) {
                        let [plusdata, plusdataComps] = TDTtranslator.#toBINARYEncodePlusData(internalMap.plusdata, this.tdtData.table.F, true)
                        for (let d of plusdata) finalOutputArray.push(d);
                        for (let d of plusdataComps) outputArrayEntries.push(d);
                    }
                    break;
                }
                case "GS1_AI_JSON": {
                    // TDT grammar has "} as the last element - so that has to be fixed up
                    finalOutputArray[finalOutputArray.length - 1] = '"';
                    finalOutputArray.push(TDTtranslator.#toJSONEncodePlusData(internalMap.plusdata));
                    outputArrayEntries.push('AIDC+');
                    finalOutputArray.push("}");
                    outputArrayEntries.push('literal');
                    break;
                }
                case "GS1_DIGITAL_LINK": {
                    // Need to determine if the output already has ?
                    if (outputOption.grammar.includes('?')) {
                        finalOutputArray.push("&");
                    } else {
                        finalOutputArray.push("?");
                    }
                    outputArrayEntries.push('literal');
                    finalOutputArray.push(TDTtranslator.#toDigitalLinkEncodePlusData(internalMap.plusdata));
                    outputArrayEntries.push('AIDC+');
                    break;
                }
            }
        }

        console.debug("finalOutputArray = "+JSON.stringify(finalOutputArray));
        let returnString = finalOutputArray.join("");

        // Digital Link URIs may need post processing to get key qualifiers in place.
        if ((outputLevel == "GS1_DIGITAL_LINK") && (outputLevelData.gs1DigitalLinkKeyQualifiers.length > 0)) {
            returnString = digitalLinkPostFormat(returnString, outputLevelData.gs1DigitalLinkKeyQualifiers);
        }

        if (hexOut) returnString = this.bin2hex(returnString);

        console.debug("output string = "+returnString);
        if (options.hasOwnProperty('returnArray') && (options['returnArray'])) {
            return [finalOutputArray, outputArrayEntries];
        } else {
		    return returnString;
        }
    }

    schemes() {
	    if (this.tdtData) {
		    return Object.keys(this.tdtData.scheme);
    	} else {
	    	return [];
	    }
    }

    bin2hex(inputBinaryString) {
        let outputHexString = "";

        if (!regexBinaryString.test(inputBinaryString)) {
            throw new Error("Input is not binary - only 0 or 1 allowed: "+inputBinaryString);
        }

        for (let t = 0; t < inputBinaryString.length; t += 4) {
            let binary = inputBinaryString.substr(t, 4);
            binary = postPad(binary, "0", 4);
            outputHexString += parseInt(binary, 2).toString(16).toUpperCase();
        }
        return outputHexString;
    }

    hex2bin(inputHexString) {
        let outputBinaryString = "";

        if (!regexHexadecimal.test(inputHexString)) {
            throw new Error("Input is not hexadecimal - only 0-9A-F allowed");
        }

        for (let t = 0; t < inputHexString.length; t++) {
            outputBinaryString += prePad(parseInt(inputHexString.charAt(t), 16).toString(2), "0", 4);
        }
        return outputBinaryString;
    }

}


// need to do this for all const defined above

TDTtranslator.prePad = prePad;
TDTtranslator.toBinaryUsingTableF = toBinaryUsingTableF;
TDTtranslator.fromBinaryUsingTableF = fromBinaryUsingTableF;


function byFile(filename) {
		return function (element) {
			if (element['file'] == filename) { return true; }
		}
}

function byOptionKey(optionkey) {
		return function (element) {
			if (element['optionKey'] == optionkey) { return true; }
		}
}


function unwrapDataByFilename(data,key) {
	return data.filter(byFile(key))[0].data;
}

/*
 * Create hash of "rows" data from table, where key is column "a"
 */
function unwrapDataRowsByFilename(data, key) {
    let rows = {};
    for (let row of unwrapDataByFilename(data, key).rows) {
        rows[row.a] = row;
    }
    return rows;
}
