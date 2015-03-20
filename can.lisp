;;
;;  can - semantic rule-based access control library.
;;
;;  Copyright 2013,2014 Thomas de Grivel <billitch@gmail.com>
;;
;;  Permission to use, copy, modify, and distribute this software for any
;;  purpose with or without fee is hereby granted, provided that the above
;;  copyright notice and this permission notice appear in all copies.
;;
;;  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
;;  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
;;  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
;;  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
;;  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
;;  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
;;  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
;;

(in-package #:can)

(defvar *rules*)

(defun reset-rules ()
  (setq *rules* nil))

#+nil
(reset-rules)

(defmacro define-permission ((subject permission action object) &body specs)
  `(push '((,subject ,permission ,action ,object) . ,specs)
	 *rules*))

#+nil
(define-permission (?user :can :edit ?module)
  (?user :is-a 'user
	 'user.status :active)
  (?module :is-a 'module
	   'module.owner ?user))
#+nil
(define-permission (:everyone :can :view :all))
#+nil
(rule-bindings '?s '?a '?o (first *rules*))

(defun can/rule (subject action object rule)
  (destructuring-bind ((s p a o) &body specs) rule
    (let (bindings constants)
      (flet ((unify (r x wild)
	       (if (facts:binding-p r)
		   (push (cons r x) bindings)
		   (push `(or (eq ,r ,wild)
                              (lessp:lessp-equal ,r ,x))
			 constants))))
	(unify o object :all)
	(unify a action :admin)
	(unify s subject :everyone))
      `(when (and ,@constants
		  ,@(sublis bindings specs))
	 ,p))))

#+nil
(can/rule 'user ':edit 'object (second *rules*))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let (can-lambda)

    (defun can (action &optional (object :all) (user :anonymous))
      (if can-lambda
	  (funcall can-lambda action object (or user :anonymous))
	  (error "Please call CAN:COMPILE-RULES.")))

    (defun compile-rules ()
      (setq can-lambda
	    (compile nil `(lambda (action object user)
			    (eq (or ,@(mapcar (lambda (rule)
						(can/rule 'user 'action
							  'object rule))
					      *rules*))
				:can)))))))
