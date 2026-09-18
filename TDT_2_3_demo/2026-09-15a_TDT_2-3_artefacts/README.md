# Tag Data Translation - draft artefacts

## Introduction
This subdirectory contains draft artefacts in both XML and JSON format.  These still require further testing and are subject to further changes and improvement.

## Artefacts for EPC schemes
The artefacts for EPC schemes introduced in GS1 Tag Data Standard v2.0 all include the '+' symbol in their filename immediately before the filename suffix, either .xml or .json
The artefacts for EPC schemes introduced in GS1 Tag Data Standard before v2.0 do not include '+' in their filename and typically indicate a fixed number of bits, e.g. SSCC-96, SGTIN-198 or a variable-length schemes such as ADI-var .

The following TDT artefacts have all been created recently and were not present in the last published release of TDT 1.6:

<table>
  <thead>
  <tr><th colspan="2">EPC schemes already existing before TDS 2.0</th></tr>
  <tr><th>XML format</th><th>JSON format</th></tr>
  </thead>
  <tbody>
  <tr><td>GDTI-174.xml</td><td>GDTI-174.json</td></tr>
  <tr><td>GSRNP-96.xml</td><td>GSRNP-96.json</td></tr>
  <tr><td>ITIP-110.xml</td><td>ITIP-110.json</td></tr>
  <tr><td>ITIP-212.xml</td><td>ITIP-212.json</td></tr>
  <tr><td>SGCN-96.xml</td><td>SGCN-96.json</td></tr>
  </tbody>
</table>

<table>
  <thead>
  <tr><th colspan="2">EPC schemes introduced in TDS 2.0</th></tr>
  <tr><th>XML format</th><th>JSON format</th></tr>
  </thead>
  <tbody>
  <tr><td>CPI+.xml</td><td>CPI+.json</td></tr>
  <tr><td>DSGTIN+.xml</td><td>DSGTIN+.json</td></tr>
  <tr><td>GDTI+.xml</td><td>GDTI+.json</td></tr>
  <tr><td>GIAI+.xml</td><td>GIAI+.json</td></tr>
  <tr><td>GRAI+.xml</td><td>GRAI+.json</td></tr>
  <tr><td>GSRN+.xml</td><td>GSRN+.json</td></tr>
  <tr><td>GSRNP+.xml</td><td>GSRNP+.json</td></tr>
  <tr><td>ITIP+.xml</td><td>ITIP+.json</td></tr>
  <tr><td>SGCN+.xml</td><td>SGCN+.json</td></tr>
  <tr><td>SGLN+.xml</td><td>SGLN+.json</td></tr>
  <tr><td>SGTIN+.xml</td><td>SGTIN+.json</td></tr>
  <tr><td>SSCC+.xml</td><td>SSCC+.json</td></tr>
  </tbody>
</table>

At present, the old 64-bit EPC schemes are unlikely to be supported in TDT 2.0 onwards since they are no longer detailed in TDS 2.0.

TDT definition files are hierarchical data structures, where each 'level' expressed a different way of representing the same instance identifier.
In TDT 1.6, 'level' elements were defined for BINARY, TAG_ENCODING, PURE_IDENTITY, LEGACY, LEGACY_AI, ELEMENT_STRING, ONS_HOSTNAME.
Some of this terminology may change, since over 15 years have passed since TDT 1.0 was initially drafted and the word 'LEGACY' may be considered unhelpful in late 2022.

All TDT artefacts for EPC schemes based on GS1 identifiers now include a new 'level' of representation for GS1_DIGITAL_LINK
The previous 'level' for ONS_HOSTNAME has now been removed from all artefacts for EPC schemes
No 'level' for TAG_ENCODING or PURE_IDENTITY is defined for the new EPC schemes introduced in TDS 2.0 since TDS 2.0 itself does not define a tag-encoding URN or pure identity URN format for those new schemes.

The following further changes are currently under consideration:
* Rename the 'level' for LEGACY as BARE_IDENTIFIER
* Rename the 'level' for LEGACY_ALT as BARE_IDENTIFIER_ALT  (appears only in TDT definition files for GRAI because of troublesome pad 0 before GRAI)
* Drop the 'level' that was named 'ELEMENT_STRING'
* Retain the 'level' that was named 'LEGACY_AI' but rename this as 'ELEMENT_STRING'.  The reason for this is that this level encloses the GS1 Application Identifier key (e.g. (01), (00)) within round brackets and we avoid any problems in expressing group separator characters in the regular expressions.  That would have been problematic for CPI-var, since the CPI itself is variable-length.

## Tables
The eight files (TDT_TableB, TDT_TableE, TDT_TableF, TDT_TableK) in JSON and XML are machine-readable versions of the tables that (should all) appear in TDS 2.2.  
These are essential for use with the new EPC schemes introduced in TDS 2.0, since these support variable-length components and make use of encoding indicators and length indicators where appropriate.  
Table F is probably the most important and provides binary formatting information for each GS1 Application Identifier, depending on whether the value (or two-part component within some values) is fixed-length or variable-length, numeric or alphanumeric.  
The TDT files for the new EPC schemes introduced in TDS 2.0 all include a new feature 'encodedAI', which indicates which GS1 Application Identifier(s) are encoded to construct the main EPC instance identifier.  This represents the handoff to use of Table F, since it is impractical for the TDT files for the new EPC schemes to express all possible combinations of lengths and encodings of variable-length fields.  Further guidance about this has been written in the human-readable TDT 2.2 standard, including diagrams showing worked examples.  Table F and Table K also used when encoding or decoding additional AIDC data in binary after the end of the EPC instance identifier.  TDS 2.2 already explains how to do this and TDT will reference that section of TDS 2.2, while providing additional guidance about how the machine-readable version of Table F may be used in practice, together with supporting tables K, E and B.

<table>
<thead>
<tr><th colspan="2">Tables provided in TDT 2.2</th></tr>
<tr><th>Table</th><th>Purpose</th></tr>
</thead>
<tbody>
<tr><td>F</td><td>format details for binary encoding of GS1 Application Identifiers in +AIDC data after EPC or within the new EPC schemes introduced in TDS 2.0</td></tr>
<tr><td>K</td><td>length of a GS1 Application Identifier key (2,3,4 digits, e.g. (8003) = 4 digit key) based on the initial two digits (e.g. '80')</td></tr>
<tr><td>E</td><td>encoding indicator and methods introduced in TDS 2.0 for new EPC schemes and +AIDC data, together with supported character sets</td></tr>
<tr><td>B</td><td>the number of bits required to encode a value in binary for a specified length of characters and encoding method.</td></tr>
</tbody>
</table>

### Note about backslash \\ - change to double backslash \\\\ from TDT 2.0 onwards
The TDT artefact files for EPC schemes include regular expression patterns for matching the input representation of an EPC and including grouping patterns for extracting various sequences of bits or characters that are then further processed for construction of the output representation.
Within regular expressions, various characters (including () {} [] . ? + * ) have special meanings and backslash  \\  is typically used to escape those characters when they are being used literally, such as when a literal dot is used as a structural delimiter within an EPC URN, having a different meaning from dot within a regular expression which means 'match any character'.  In order for the JSON format of the TDT definition files to be valid, every backslash character appearing within a double-quoted string must be a double backslash  \\\\ , so the new definition files should use a double backslash throughout for all pattern strings, whether the file is in JSON or XML, for consistency.  Note that in TDT 1.6, a single backslash was used.  Implementations of TDT migrating to v2.0 onwards need to be aware of this change to double backslash in the definition files.

### Note about percent-encoding of symbol characters in pure-identity URN, tag-encoding URN and GS1 Digital Link URIs

TDS requires the following symbol characters to be escaped when expressed within URNs:  " & / < > ? # %

GS1 Digital Link standard requires the following characters to be escaped when expressed within URLs / Web URIs:  ! & ' ( ) * + , / : ; < = > ? # %

TDT definition files therefore include four new rule functions URNENCODE, URNDECODE, URLENCODE, URLDECODE and these are used within the `level` where `type` is `PURE_IDENTITY`, `TAG_ENCODING` or `GS1_DIGITAL_LINK`.

Regular expression patterns appearing within the `pattern` of each `option` have also been updated accordingly.  In such scenarios, the patterns that permit symbol characters that need to be escaped within URNs or URLs are not expressed as non-capturing groups using a character class (for those characters that do not need to be percent-encoded) followed by pipe alternation of multiple `%hh` sequences where h is a hexadecimal character 0-9A-F, such as `%2F` as the percent-encoding of a forward-slash / solidus character.  

This updated approach ensures that each percent-encoded symbol character still counts as one character each though it may need to be encoded within a URN / URL / Web URI as a 3-character %hh sequence.  The revised regular expression patterns have been tested to ensure that they enforce the correct maximum character count limits expressed in the GS1 General Specifications, e.g. the serial number corresponding to AI (21) may have up to 20 characters - so even if it consisted of something like this 

"%22%26%2F%3C%3E%3F%25%22%26%2F%3C%3E%3F%25%22%26%2F%3C%3E%3F" ,

this still validates against a pattern such as `/^((?:[A-Za-z0-9!'()*+,.:;=_-]|%22|%26|%2F|%3C|%3E|%3F|%25){1,20})$/` even though it consists of 60 bytes but still only represents 20 symbol characters, whereas 

"%22%26%2F%3C%3E%3F%25%22%26%2F%3C%3E%3F%25%22%26%2F%3C%3E%3Fa"

does not validate against that pattern because it represents 21 characters, which exceeds the limit of 20 characters.

### Note about new optional property/attribute `gcpOffset` within `field`
Within the TDT definition files for old-style EPC schemes defined before TDS 2.0, within `level` objects for `ELEMENT_STRING`, `GS1_DIGITAL_LINK` or `BARE_IDENTIFIER` and in situations where `field` corresponds to a primary GS1 identification key such as GTIN, SSCC, GLN, a new attribute, `gcpOffset` has been included within `field`.  The purpose of this is two-fold:
1. to indicate that the value of this field contains a primary GS1 identification key
2. to indicate whether the GS1 Company Prefix appears at the start of the value string (`gcpOffset` is 0) or after an indicator digit or extension digit (`gcpOffset` is 1).

This is intended to support TDT implementations that make use of additional resources such as the GS1 Company Prefix Length lookup tables at https://www.gs1.org/standards/bc-epc-interop in order to determine the length of the GS1 Company Prefix in order to populate the value of one of the `requiredParsingParameters`, namely `gs1companyprefixlength`, in order to select the most appropriate `option` object to use in situations where the input format is `ELEMENT_STRING`, `GS1_DIGITAL_LINK` or `BARE_IDENTIFIER` and the output format is one of `BINARY`, `TAG_ENCODING` or `PURE_IDENTITY` in older EPC schemes defined before TDS 2.0, in which the length of the GS1 Company Prefix needed to be known, in order to correctly construct the binary encoding, tag-encoding URN or pure-identity URN formats.

