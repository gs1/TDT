/**
 * @fileoverview GS1 Digital Link Resolver App Controller (Minimal Version).
 */

const { createApp, markRaw } = Vue;

createApp({
    data() {
        return {
            myTDTencoder: null,
            isInitialized: false,
            inputString: '',
            copied: false,
            demos: {
                eh: 'https://example.com/eh30164596f40c0e5cbe991a83',
                ex: 'https://example.com/exMBZFlvQMDly-mRqD'
            }
        };
    },

    computed: {
        translationData() {
            if (!this.isInitialized || !this.inputString) return { result: null, error: null };
            
            try {
                // Autodetect using TDTtranslator
                const detected = this.myTDTencoder.autodetect(this.inputString);
                if (!detected || detected.length === 0) {
                    return { result: null, error: 'Failed to match input to any valid EPC scheme' };
                }
                
                const match = detected[0];
                
                // Translate the input to GS1_DIGITAL_LINK
                const result = this.myTDTencoder.translate(this.inputString, match.scheme, 'GS1_DIGITAL_LINK');
                return { result, error: null };
            } catch (e) {
                return { result: null, error: e.message || e.toString() };
            }
        },

        result() {
            return this.translationData.result;
        },

        error() {
            return this.translationData.error;
        }
    },

    methods: {
        loadDemo(key) {
            this.inputString = this.demos[key];
        },

        copyResult() {
            if (!this.result) return;
            navigator.clipboard.writeText(this.result).then(() => {
                this.copied = true;
                setTimeout(() => {
                    this.copied = false;
                }, 1500);
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        }
    },

    mounted() {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('input')) {
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
