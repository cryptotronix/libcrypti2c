(define-module (ci2c configzone)
  #:version (0 1)
  #:use-module (sxml simple)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:export (xml-file->config-bv))

(define hexstring->intlist
  (lambda [hexstring]
    (map (lambda (x) (string->number x 16)) (string-tokenize hexstring))))

(define elementstr->elementint
  (lambda [element]
    (cons (car element) (list (hexstring->intlist (cadr element)) ))))

(define xml-file-port->config-bv
  (lambda [port]
    (let* ([top (xml->sxml port)]
           [config (filter list? (caddr top))]
           [byte-list (map (lambda [x] (elementstr->elementint x)) config)])
      (u8-list->bytevector (concatenate (map cadr byte-list))))))

(define xml-file->config-bv
  (lambda [filename]
    (call-with-input-file filename xml-file-port->config-bv)))
