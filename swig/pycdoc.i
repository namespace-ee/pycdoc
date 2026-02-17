/*
 * pycdoc - Python-specific SWIG interface for libcdoc
 *
 * This wraps the upstream libcdoc.i and adds Python-specific
 * camelCase → snake_case renaming.
 */

/* Global camelCase → snake_case renaming for all functions and methods.
   Must appear BEFORE %include of upstream interface. */
%rename("%(undercase)s", %$isfunction, %$not %$isconstructor, %$not %$isdestructor) "";
%rename("%(undercase)s", %$ismember, %$not %$isenumitem, %$not %$isconstant, %$not %$isconstructor, %$not %$isdestructor, %$not %$isenum) "";

/* Include the upstream libcdoc SWIG interface */
%include "libcdoc.i"
