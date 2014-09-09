(define l (list #x07 #x02 #x80 #x10 #x00))
(define a (list #x0B #x12 #x00 #x04 #x00 #xC0 #x00 #xAA #x00))

(add-to-load-path "/home/jbd/repos/libcrypti2c/crypti2c/scheme/")
(add-to-load-path ".")
(use-modules (ci2c configzone)
             (rnrs bytevectors))

(load "testing.scm")

(test-begin "crc-test")

(test-equal (bytevector->hex-string (ci2c-crc16 (u8-list->bytevector a))) "83:0d")

(test-end "crc-test")
