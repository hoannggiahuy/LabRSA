# LabRSA
Cho phép người dùng mã hóa, giải mã file và thực hiện ký số, xác minh chữ ký số sử dụng các thuật toán AES và RSA.
![image](https://github.com/user-attachments/assets/4f4c6575-749c-4ca7-8905-c06fe9ca27b0)
Chọn file, nhập mật khẩu
Mã hóa | Giải mã
Ký Số:
Dropdown chọn:
Tạo khóa RSA
Ký dữ liệu
Xác minh chữ ký
![image](https://github.com/user-attachments/assets/b4135549-9c55-409c-8674-9e86db17fcb6)
Tạo một cặp khóa RSA (2048 bit)
Trả về:
private_key: Khóa riêng
public_key: Khóa công khai
Nhận:
Dữ liệu (chuỗi bytes)
Khóa riêng (private key)
Dùng thuật toán băm SHA256 -> ký với PKCS#1 v1.5
Trả về chữ ký (base64)
Xác minh xem chữ ký có hợp lệ với dữ liệu và khóa công khai hay không
Trả về True nếu chữ ký đúng, ngược lại False
