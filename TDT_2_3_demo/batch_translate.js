/**
 * batch_translate.js - High-Performance Headless GS1 Identifier Translation
 * 
 * Minimal deployment requirements:
 *   1. TDTtranslator.js (Core engine)
 *   2. schemas/ (Directory containing manifest.json, 9 lookup tables, and 47 scheme definitions)
 * 
 * Run:
 *   node batch_translate.js
 */

const TDTtranslator = require('./TDTtranslator.js');

async function main() {
  console.log('Initializing headless TDT 2.3 engine...');
  const startTime = Date.now();
  
  // 1. Single engine instance (reuse across all translations)
  const translator = new TDTtranslator();
  await translator.initialized;
  translator.processData();
  
  console.log(`Engine ready in ${Date.now() - startTime}ms. Active schemes: ${Object.keys(translator.tdtData.scheme).length}`);

  // 2. Input array of heterogeneous GS1 identifiers
  const inputQueue = [
    { id: 'item-01', input: 'urn:epc:id:sgtin:0614141.112345.400' },
    { id: 'item-02', input: 'https://id.gs1.org/01/09521234123453/21/32a%2Fb' },
    { id: 'item-03', input: '3074257BF4003E0000000190' },
    { id: 'item-04', input: 'urn:epc:id:sscc:0614141.1234567890' },
    { id: 'item-05', input: 'https://id.gs1.org/00/106141412345678908' }
  ];

  // 3. Translation options (essential for multi-AI compaction & prefix determination)
  const defaultOptions = {
    filter: 0,
    gs1companyprefixlength: 7,
    uriStem: 'https://id.gs1.org'
  };

  // 4. Process the batch
  const batchStart = Date.now();
  const results = [];

  for (const item of inputQueue) {
    const itemStart = Date.now();
    
    // Step A: Detect scheme and input syntax level
    const detected = translator.autodetect(item.input);
    if (!detected || detected.length === 0) {
      results.push({
        id: item.id,
        input: item.input,
        success: false,
        error: 'No matching GS1 TDS scheme regex found'
      });
      continue;
    }

    const primaryMatch = detected[0];
    const scheme = primaryMatch.scheme;
    const sourceLevel = primaryMatch.level;

    // Step B: Translate into target representations with error boundaries
    const targets = ['HEX', 'BINARY', 'GS1_DIGITAL_LINK', 'BARE_IDENTIFIER', 'PURE_IDENTITY', 'TAG_ENCODING'];
    const outputs = {};
    const errors = {};

    for (const targetLevel of targets) {
      try {
        outputs[targetLevel] = translator.translate(item.input, scheme, targetLevel, defaultOptions);
      } catch (err) {
        // Levels unsupported by a specific scheme (e.g., PURE_IDENTITY on multi-AI SGTIN++) are caught gracefully
        errors[targetLevel] = err.message;
      }
    }

    results.push({
      id: item.id,
      input: item.input,
      detectedScheme: scheme,
      detectedLevel: sourceLevel,
      success: true,
      outputs,
      unsupportedLevels: Object.keys(errors),
      durationMs: Date.now() - itemStart
    });
  }

  const batchDuration = Date.now() - batchStart;
  console.log(`\nBatch translation complete: ${results.length} items in ${batchDuration}ms (${(batchDuration / results.length).toFixed(2)}ms/item)`);
  console.log(JSON.stringify(results, null, 2));
}

main().catch(console.error);
