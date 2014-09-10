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
