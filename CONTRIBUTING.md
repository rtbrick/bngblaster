# Contributing to BNG Blaster

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to the BNG Blaster project. 
These are mostly guidelines, not rules. Use your best judgment, and feel free to 
propose changes to this document in a pull request.

## Work Flow

If you have added or modified code, please make sure the code compiles 
without warnings before submitting. Our automated testing runs CMake on
all the pull requests, so please be sure that your code passes before 
submitting. 

Pull requests are only accepted to the development branch (`dev`). From
here we run a variety of regression tests before changes will be merged
to main branch (`main`) and finally released.

You can open draft pull requests for work in progress changes or to ask
for early review or help. 
 
## Coding Conventions

### File Conventions

Please use the directory structure of the repository and 
strictly use snake_case (underscore_separated) in filenames.

### Indentation

Our standard indentation is 4 spaces per level. Most editors 
can be set up to do the right indentation for you automatically.

### Comments

Please conform to Doxygen standard and document 
the code as much as possible.

```c
/** 
 * <Function Description>
 *
 * @param p1 <Parameter Description>
 * @param p2 <Parameter Description>
 * @return <Return Value Description>
 */
void *
example_function(void *p1, void *p2)
{
    /** ... */
    return NULL;
}
```

### Macro Definitions

Macro names (`#define`) should be all UPPER CASE for readability.

### Data Types

Use portable fixed-with C99 data types define in `stdint.h` or `stddef.h`. 
This makes code more portable since the sizes of types (short, int, long, long long) 
can vary between platforms, compilers and ABIs. These standard types are guaranteed 
to be the size they advertise and are available since C99.

Width | Unsigned | Signed
----- | -------- | ------
8-bit | uint8_t | int8_t
16-bit | uint16_t | int16_t
32-bit | uint32_t | int32_t
64-bit | uint64_t | int64_t
