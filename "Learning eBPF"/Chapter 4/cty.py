import ctypes as ct

py_int = 54
print(type(py_int))

my_int = ct.c_int(42)

# Access and modify the integer value
print(my_int.value)
print(type(my_int.value))

my_int.value = 100
print(my_int.value) 

# Create a buffer of size 20 with an initial string value
buffer = ct.create_string_buffer(20, b"Hello, World")
print(buffer)
# Modify the buffer
#buffer.raw[:5] = b"Hi, "
print(buffer.value)

buffer = ct.create_string_buffer(20)
ct.memmove(buffer, b"Hello, World", len(b"Hello, World"))
# Modify the buffer using memmove
ct.memmove(ct.byref(buffer, 5), b"Hi, ", len(b"Hi, "))
print(buffer.value)

buffer = ct.create_string_buffer(12, b"Hello, World")
print(buffer.value)
# Modify the buffer using memmove
ct.memmove(ct.byref(buffer, 0), b"Hi, ", len(b"Hi, "))
print(buffer.value)