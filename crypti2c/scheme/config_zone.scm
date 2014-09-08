(use-modules (sxml simple))
(use-modules (rnrs bytevectors))
(use-modules (sfri sfri-1))

;; (define p (open-input-file "/home/jbd/config.xml"))
;; (define top (xml->sxml p))
;; (define config (filter list? (caddr top)))

;; (define config-len
;;   (lambda [element-list]
;;     (reduce + 0 (map
;;                  (lambda (x) (length (cadr x))) element-list))))

(define hexstring->intlist
  (lambda [hexstring]
    (map (lambda (x) (string->number x 16)) (string-tokenize hexstring))))

(define elementstr->elementint
  (lambda [element]
    (cons (car element) (list (hexstring->intlist (cadr element)) ))))


;; (define new
;;   (map (lambda [x]
;;          (elementstr->elementint x)) (filter list? (caddr top))))

;;(u8-list->bytevector (concatenate (map cadr new)))

(define xml-file-port->config-bv
  (lambda [port]
    (let* ([top (xml->sxml port)]
           [config (filter list? (caddr top))]
           [byte-list (elementstr->elementint config)]
           (u8-list->bytevector (concatenate (map cadr byte-list)))))))

(define xml-file->config-bv
  (lambda [filename]
    (call-with-input-file filename proc)))
