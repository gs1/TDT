# TDT

Demo web interface implementation of [TDS 2.2](https://ref.gs1.org/standards/tds/2.2.0/) and [TDT 2.2](https://ref.gs1.org/standards/tdt/2.2.0/) , using the [TDT 2.2 translation files](https://ref.gs1.org/standards/tdt/artefacts).

[Online demo tool available here](https://gs1.github.io/TDT/demo/)

The online demo tool makes use of a JavaScript TDT library / toolkit at https://github.com/gs1/TDT/blob/main/demo/TDTtranslator.js that can be used independently of the Web interface.

The TDT library / toolkit depends on reading a set of normative machine-readable artefacts at https://github.com/gs1/TDT/blob/main/demo/TDT_JSON_artefacts.zip that provide the definitions for each EPC scheme and their representations in binary format as well as equivalences as GS1 Digital Link URIs, element strings and (for older schemes defined before TDS 2.0) EPC URN format for pure identity and tag encoding.

Lines 69-154 of https://github.com/gs1/TDT/blob/main/demo/index.html provide some guidance about how the library can be used.

A new instance of the toolkit can be constructed as follows:

`const myTDTencoder = new TDTtranslator();`

It then needs to be initialised and process the TDT data read from the artefacts, as follows:

```
myTDTencoder.initialized.then(() => {
	myTDTencoder.processData(); // Call other functions after initialization
  // other functions here
  }
).catch(error => {
	console.error('Error initializing library:', error);
});
```

The toolkit provides an `autodetect` method to auto-detect EPC schemes that potentially match the input string provided, as well as detecting the input representation format, such as BINARY, GS1_DIGITAL_LINK, etc. and specific options within the matching input level (which is used in older EPC schemes before TDS 2.0 to handle the partition tables that depend on the length of the GS1 Company Prefix - and in the new DSGTIN+ EPC scheme, to handle different meanings of the prioritised date field).

The toolkit provides a `translate` method to translate the input into a desired output format.

In order to support translation of many older EPC schemes introduced before TDS 2.0, where there is a need to know the length of the GS1 Company Prefix when translating toward binary or the older EPC URN formats, the demo folder includes a cached copy of the table that is currently provided at
https://www.gs1.org/docs/gcp_length/gcpprefixformatlist.json to assist with the determination of the length of the GS1 Company Prefix based on lookup of the initial digits.  Note that the table at https://www.gs1.org/docs/gcp_length/gcpprefixformatlist.json is only partially complete and is missing data from some countries.
In situations where an older EPC scheme is being used and the length of the GS1 Company Prefix cannot be determined automatically from this table, the length will need to be specified explicitly as the `gs1companyprefixlength` field of the `options` parameter to the `translate` method.


