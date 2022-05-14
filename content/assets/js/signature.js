Vue.createApp({
  delimiters: ['[[', ']]'],
  data() {
    return {
      errors: { // Errors texts
        notSert: 'Сертефикат должен быть в форматах: .rem, .pev или .crt',
        sertNull: 'Выберите сертификат',
        docNull: 'Выберите документ',
        isImg: 'Недопустим файл данного формата',
        isSpace: 'В название файла недопустим пробел'
      },
      validators: { // Toach state values
        isSertTouched: false,
        isDocTouched: false
      },
      docName: '',
      sertName: '',
      isDoc: false,
      isSert: false,
      messageNumber: 1,
      messages: ['', 'Выберите документ, который необходимо подписать', 'Выберите сертификат', 'Подпишите']
    }
  },
  methods: {
    // Setting input values
    setDoc(e) {
      this.isDoc = true

      let Doc = e.currentTarget.value.split('\\').pop()
      if( Doc.length > 20 ) this.docName = Doc.substr(0, 20)
      else this.docName = Doc

      if(this.messageNumber < 3) this.messageNumber = 2
    },
    setSert(e) {
      this.isSert = true

      let Sert = e.currentTarget.value.split('\\').pop()
      if( Sert.length > 20 ) this.sertName = Sert.substr(0, 20)
      else this.sertName = Sert

      if(this.messageNumber < 3) this.messageNumber = 3
    },

    // Validators
      // Setting touch
    setDocTouch() {
      if(!this.validators.isDocTouched) this.validators.isDocTouched = true
    },
    setSertTouch() {
      if(!this.validators.isSertTouched) this.validators.isSertTouched = true
    },

      // Checking certificate
    checkValidSert() {
      if(this.validators.isSertTouched) return  !(this.sertName.includes('.rem') || this.sertName.includes('.pem') || this.sertName.includes('.crt')) 
    },
    checkNullSert() {
      if(this.validators.isSertTouched) return !this.sertName
    },

      // Checking document
    checkNullDoc() {
      if(this.validators.isDocTouched) return !this.docName
    },
    checkValidDoc() {
      const img = ['psd', 'tiff',  'bmp', 'jpeg', 'jpg', 'gif', 'eps', 'png', 'pict', 'ico', 'pcx', 'cdr', 'ai', 'raw', 'svg', 'webp', 'avif']
      if(this.validators.isDocTouched) return img.some(format => this.docName.includes(format)) || img.some(format => this.docName.includes(format.toUpperCase()))
    },
    checkNameDoc() {
      if(this.validators.isDocTouched) return this.docName.includes(' ')
    },

      // Common validation
    checkNull() {
      return !this.docName || !this.sertName
    },
    checkValid() {
      return this.checkValidSert() || this.checkNull() || this.checkValidDoc() || this.checkNameDoc()
    }
  },
}).mount('#workplace')





