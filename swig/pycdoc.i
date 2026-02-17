/*
 * pycdoc - Python-specific SWIG interface for libcdoc
 *
 * This wraps the upstream libcdoc.i and adds Python-specific
 * template instantiations and director support.
 */

/* Global camelCase → snake_case renaming for all functions and methods.
   Must appear BEFORE %include of upstream interface. */
%rename("%(undercase)s", %$isfunction, %$not %$isconstructor, %$not %$isdestructor) "";
%rename("%(undercase)s", %$ismember, %$not %$isenumitem, %$not %$isconstant, %$not %$isconstructor, %$not %$isdestructor, %$not %$isenum) "";

/* Include the upstream libcdoc SWIG interface */
%include "libcdoc.i"

/* Python-specific std::vector template instantiations */
%template(ByteVector) std::vector<uint8_t>;
%template(ByteVectorVector) std::vector<std::vector<uint8_t>>;
%template(StringVector) std::vector<std::string>;
