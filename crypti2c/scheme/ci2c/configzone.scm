(define-module (ci2c configzone)
  #:version (0 1)
  #:use-module (sxml simple)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 format)
  #:export (xml-file->config-bv
            ci2c-crc16
            bytevector->hex-string))

(load-extension "/usr/local/lib/libcrypti2c-0.1" "init_crypti2c")

(define (is-ecc-content? x)
  "Predicate to test if the symbol X matches the start symbol
for the ECC108 Content block"
  (if (equal? 'ECC108Content.01 x)
      #t
      #f))

(define (get-ecc108-content sxmldata)
  "Returns the ECC108 list from the entire SXMLDATA list"
  (let ([top-list (cdr sxmldata)])
    (car (filter (lambda [x] (is-ecc-content? (car x))) top-list))))

(define (get-config-data ecc108-content)
  "Returns the inner list of the actual data"
  (caddr ecc108-content))

(define (get-config-elements config-data)
  "Strips out extraneous information in the list and leaves just lists of
elements"
  (filter list? config-data))

(define (hexstring->intlist hexstring)
  "Converts the hexstring in XML data to an int list"
  (map (lambda (x) (string->number x 16)) (string-tokenize hexstring)))


(define (elementstr->elementint element)
  "Converts the elements, which are strings of hex into an integer list"
  (cons (car element) (list (hexstring->intlist (cadr element)) )))

(define (xml-file-port->config-bv port)
  "Take the open XML file PORT, parse it, extract the configuration zone,
and return the byte vector of the zone"
  (let* ([top (xml->sxml port)]
         [config (get-config-elements (get-config-data (get-ecc108-content top)))]
         [byte-list (map (lambda [x] (elementstr->elementint x)) config)])
    (u8-list->bytevector (concatenate (map cadr byte-list)))))

(define (xml-file->config-bv filename)
  "Load the xml-file FILENAME and return a byte vector BV containing the
contiguous bytes of the entire configuration zone"
  (call-with-input-file filename xml-file-port->config-bv))

;;useful
;; From https://raw.githubusercontent.com/artyom-poptsov/guile-ssh/master/ssh/key.scm
(define (bytevector->hex-string bv)
  "Convert bytevector BV to a colon separated hex string."
  (string-join (map (lambda (e) (format #f "~2,'0x" e))
                    (bytevector->u8-list bv))
               ":"))

;; commands
(define-immutable-record-type <atsha204-command>
  (make-atsha204-command opcode param1 param2 data)
  atsha204-command?
  (opcode atsha204-command-opcode)
  (param1 atsha204-command-param1)
  (param2 atsha204-command-param2)
  (data atsha204-command-data))

(define (make-zone-bits zone-sym)
  (case zone-sym
    ((CONFIG-ZONE) #x00)
    ((OTP-ZONE) #x01)
    ((DATA-ZONE) #x02)))

(define (make-write4-cmd zone addr data)
  (make-atsha204-command 'COMMAND-WRITE (make-zone-bits zone) addr data))

(define opcodes (make-hash-table))

(hash-set! opcodes 'COMMAND-WRITE #x12)

(define (atsha204-command-apply-crc bv)
  "Apply the CRC to the already serialized command. Requires some byte moving"
  (let* ([crc (ci2c-crc16 (u8-list->bytevector (cdr (bytevector->u8-list bv))))]
         [bv-len (bytevector-length bv)]
         [crc-len (bytevector-length crc)]
         [bv-crc-len (+ bv-len crc-len)]
         [bv-crc (make-bytevector bv-crc-len)])
    (begin (bytevector-copy! bv 0 bv-crc 0 bv-len)
           (bytevector-copy! crc 0 bv-crc (- bv-crc-len crc-len) crc-len)
           bv-crc)))

(define (atsha204-command-serialize cmd)
  "Serialize the command for transmission to the device.
This applies the CRC as well."
  (let* ([len-sans-crc (+ 1 1 1 1 2 (length (atsha204-command-data cmd)))]
         [bv (make-bytevector len-sans-crc)]
         [packet-size (+ (- len-sans-crc 1) 2)]
         [COMMAND-BYTE-INDICATOR #x03])
    (begin (bytevector-u8-set! bv 0 COMMAND-BYTE-INDICATOR)
           (bytevector-u8-set! bv 1 packet-size)
           (bytevector-u8-set! bv 2
                               (hash-ref opcodes (atsha204-command-opcode cmd)))
           (bytevector-u8-set! bv 3
                               (atsha204-command-param1 cmd))
           (bytevector-u16-set! bv 4
                                (atsha204-command-param2 cmd) (endianness little))
           (if (not (null? (atsha204-command-data cmd)))
               (let ([data (u8-list->bytevector (atsha204-command-data cmd))])
                 (bytevector-copy! data 0 bv 6
                                   (length (atsha204-command-data cmd)))))
           (atsha204-command-apply-crc bv))))
