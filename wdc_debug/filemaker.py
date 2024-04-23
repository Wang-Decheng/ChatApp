def create_large_file(file_path, size_in_mb):
    with open(file_path, 'wb') as f:
        f.write(b'\0' * (size_in_mb * 1024 * 1024))

file_path = 'large_file.bin'
size_in_mb = 100
create_large_file(file_path, size_in_mb)
print(f"File '{file_path}' created with size approximately {size_in_mb} MB.")
