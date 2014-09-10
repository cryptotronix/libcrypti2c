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
  (if (equal? 'ECC108Content.01 x)
      #t
      #f))

(define (get-ecc108-content sxmldata)
  (let ([top-list (cdr sxmldata)])
    (car (filter (lambda [x] (is-ecc-content? (car x))) top-list))))

(define (get-config-data ecc108-content)
  (caddr ecc108-content))

(define (get-config-elements config-data)
  (filter list? config-data))

(define hexstring->intlist
  (lambda [hexstring]
    (map (lambda (x) (string->number x 16)) (string-tokenize hexstring))))

(define elementstr->elementint
  (lambda [element]
    (cons (car element) (list (hexstring->intlist (cadr element)) ))))

(define xml-file-port->config-bv
  (lambda [port]
    (let* ([top (xml->sxml port)]
           [config (get-config-elements (get-config-data (get-ecc108-content top)))]
           [byte-list (map (lambda [x] (elementstr->elementint x)) config)])
      (u8-list->bytevector (concatenate (map cadr byte-list))))))

(define xml-file->config-bv
  (lambda [filename]
    (call-with-input-file filename xml-file-port->config-bv)))

;;useful
;; From https://raw.githubusercontent.com/artyom-poptsov/guile-ssh/master/ssh/key.scm
(define (bytevector->hex-string bv)
  "Convert bytevector BV to a colon separated hex string."
  (string-join (map (lambda (e) (format #f "~2,'0x" e))
                    (bytevector->u8-list bv))
               ":"))
