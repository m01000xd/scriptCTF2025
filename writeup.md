# scriptCTF2025
## Plastic Shield
<img width="727" height="535" alt="image" src="https://github.com/user-attachments/assets/61164999-5774-4f79-b1a5-9750099de422" />

1 file elf64

<img width="1459" height="658" alt="image" src="https://github.com/user-attachments/assets/bac20309-6e65-4c51-8058-239f2b5a2c73" />
<img width="740" height="309" alt="image" src="https://github.com/user-attachments/assets/9659333b-d917-412d-b874-a15bda2434da" />

Load vào IDA, hàm bắt người dùng nhập 1 password, sau đó lấy 1 kí tự ở vị trí tỉ lệ 60/64 với độ dài password, hash kí tự đó bằng thuật toán crypto_blake2b, được 1 giá trị 64 byte, rồi lấy 32 byte đầu làm key, 16 byte tiếp theo lấy làm iv.

Chuỗi v14 chính là ciphertext flag đã được encrypt bằng AES_CBC. Ở dưới ta thấy gọi hàm AES_init_ctx_iv và AES_CBC_decrypt_buffer để decrypt chuỗi ciphertext ở trên với key và iv truyền vào như đã lấy ở trên.

### Script
```python3
import hashlib
from Crypto.Cipher import AES
v14 = "713d7f2c0f502f485a8af0c284bd3f1e7b03d27204a616a8340beaae23f130edf65401c1f99fe99f63486a385ccea217"
ciphertext = bytes.fromhex(v14)
for i in range(256):
    v9 = bytes([i])
    h = hashlib.blake2b(v9,digest_size=64).hexdigest()
    key = bytes.fromhex(h[:64])
    iv = bytes.fromhex(h[64:96])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    pad_len = plaintext[-1]
    if pad_len <= 0x10:
        plaintext = plaintext[:-pad_len]
    if plaintext and all(32 <= c < 127 for c in plaintext):
        print(plaintext.decode('utf-8'))
```
  ## ForeignDesign
  <img width="726" height="532" alt="image" src="https://github.com/user-attachments/assets/6eecb2af-d78f-4c8e-a2d8-8f9e44cb6b24" />

  Đề cho 1 file jar

  <img width="1747" height="677" alt="image" src="https://github.com/user-attachments/assets/a500f01a-6e6b-434e-ab4b-9b6e8172340f" />

  Kiếm 1 tool decompile file jar trên goole rồi tải xuống toàn bộ thư mục

  <img width="1575" height="905" alt="image" src="https://github.com/user-attachments/assets/2abede05-c109-4dbc-ab71-5810a9c8e3c5" />

  <img width="1117" height="641" alt="image" src="https://github.com/user-attachments/assets/b467e699-1916-4167-86bf-5be79c033a59" />
  
  Trong thư mục tải về có 2 file java, xem thử file NativeLoader.java thì thấy có load thư viện từ thư mục native, kiểm tra xem OS đang dùng là win hay linux, nếu linux thì load file .so, còn nếu windows thì load file .dll

  Còn lại 1 file Main.java:
  ```java
  package xyz.scriptctf;

import java.util.Scanner;

public class Main {
   public static int[] ll = new int[0];
   public static int[] lll = new int[0];
   public static Scanner fl;

   public static native void initialize();

   private static native void sc(char var0, int var1);

   public static int s2(char c, int i) {
      int base = c + i % 7 * 2;
      if (i % 2 == 0) {
         base ^= 44;
      } else {
         base ^= 19;
      }

      return base + (i & 1);
   }

   public static void ck(String ws) {
      if (ws.length() == ll.length + lll.length) {
         for(int i = 0; i < ws.length(); ++i) {
            int idx = (i * 5 + 3) % ws.length();
            char ch = ws.charAt(idx);
            sc(ch, i);
         }

         System.out.println("Correct!");
      } else {
         System.out.println("Incorrect!");
      }

   }

   public static void main(String[] args) {
      try {
         NativeLoader.loadLibrary();
      } catch (Exception var2) {
         var2.printStackTrace();
      }

      fl = new Scanner(System.in);
      System.out.print("Please Enter Flag: ");
      initialize();
   }
}
```
File này dùng để check flag nhập vào, nó kiểm tra xem độ dài của flag nhập vào có bằng tổng độ dài của 2 mảng khởi tạo khi gọi hàm initialize() là ll và lll không, rồi sau đó gọi hàm sc để check các kí tự nhập vào, nếu đúng thì sẽ in ra Correct, còn sai thì in ra Incorrect.
Giờ ta cần biết hàm initialize() và hàm sc() làm gì, mà 2 hàm đấy không được define trong file này mà được import từ file .so hoặc .dll được load vào như đã nêu ở trên. Vậy ta cần phân tích file .so đó

Load vào IDA:
<img width="1473" height="669" alt="image" src="https://github.com/user-attachments/assets/49f6a1d4-9ce8-44d2-902a-4ac5f7e4d8a7" />

```c
int __cdecl Java_xyz_scriptctf_Main_initialize(int a1, int a2)
{
  int v2; // ebp
  int result; // eax
  int v4; // esi
  int v5; // ebp
  int v6; // edx
  int v7; // ebp
  int v9; // edi
  int v10; // esi
  int v11; // eax
  int v12; // esi
  int v13; // edi
  int v14; // [esp+Ch] [ebp-B0h]
  int v15; // [esp+10h] [ebp-ACh]
  int v16; // [esp+14h] [ebp-A8h]
  char v17[56]; // [esp+18h] [ebp-A4h] BYREF
  char v18[108]; // [esp+50h] [ebp-6Ch] BYREF

  v2 = (*(int (__cdecl **)(int, int, void *, void *))(*(_DWORD *)a1 + 576))(a1, a2, &unk_2004, &unk_2000);
  result = (*(int (__cdecl **)(int, int, void *, void *))(*(_DWORD *)a1 + 576))(a1, a2, &unk_2003, &unk_2000);
  v16 = v2;
  if ( v2 )
  {
    v4 = result;
    if ( result )
    {
      v5 = (*(int (__cdecl **)(int, int))(*(_DWORD *)a1 + 716))(a1, 23);
      result = (*(int (__cdecl **)(int, int))(*(_DWORD *)a1 + 716))(a1, 14);
      if ( v5 )
      {
        if ( result )
        {
          v6 = v5;
          v15 = v4;
          v7 = result;
          v14 = result;
          qmemcpy(v18, " ", 0x5Cu);
          qmemcpy(v17, &unk_20E0, sizeof(v17));
          v9 = v6;
          (*(void (__cdecl **)(int, int, _DWORD, int, char *))(*(_DWORD *)a1 + 844))(a1, v6, 0, 23, v18);
          (*(void (__cdecl **)(int, int, _DWORD, int, char *))(*(_DWORD *)a1 + 844))(a1, v7, 0, 14, v17);
          (*(void (__cdecl **)(int, int, int, int))(*(_DWORD *)a1 + 616))(a1, a2, v16, v9);
          (*(void (__cdecl **)(int, int, int, int))(*(_DWORD *)a1 + 616))(a1, a2, v15, v14);
          result = (*(int (__cdecl **)(int, int, void *, const char *))(*(_DWORD *)a1 + 576))(
                     a1,
                     a2,
                     &unk_2007,
                     "Ljava/util/Scanner;");
          if ( result )
          {
            result = (*(int (__cdecl **)(int, int, int))(*(_DWORD *)a1 + 580))(a1, a2, result);
            if ( result )
            {
              v10 = result;
              v11 = (*(int (__cdecl **)(int, int))(*(_DWORD *)a1 + 124))(a1, result);
              result = (*(int (__cdecl **)(int, int, const char *, const char *))(*(_DWORD *)a1 + 132))(
                         a1,
                         v11,
                         "nextLine",
                         "()Ljava/lang/String;");
              if ( result )
              {
                result = (*(int (__cdecl **)(int, int, int))(*(_DWORD *)a1 + 136))(a1, v10, result);
                if ( result )
                {
                  v12 = result;
                  result = (*(int (__cdecl **)(int, int, _DWORD))(*(_DWORD *)a1 + 676))(a1, result, 0);
                  if ( result )
                  {
                    v13 = result;
                    result = (*(int (__cdecl **)(int, int, const char *, const char *))(*(_DWORD *)a1 + 452))(
                               a1,
                               a2,
                               "ck",
                               "(Ljava/lang/String;)V");
                    if ( result )
                    {
                      (*(void (__cdecl **)(int, int, int, int))(*(_DWORD *)a1 + 564))(a1, a2, result, v12);
                      return (*(int (__cdecl **)(int, int, int))(*(_DWORD *)a1 + 680))(a1, v12, v13);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return result;
}
```
Đây là hàm initialize() sau khi được IDA decompile lại, có vẻ khá khó hiểu, ta thử đưa AI phân tích

<img width="1024" height="630" alt="image" src="https://github.com/user-attachments/assets/bef15b6e-e12f-4502-ad15-79ac7f9a8025" />

<img width="992" height="689" alt="image" src="https://github.com/user-attachments/assets/156745c7-3cf4-4512-8b94-f047cb7cb84c" />

<img width="979" height="524" alt="image" src="https://github.com/user-attachments/assets/1e7b2f94-5a24-4de6-a4bb-039b1ab76030" />

Đã rõ ràng hơn nhiều, hàm initialize() nạp dữ liệu hằng vào 2 mảng v5 và v17, chính là 2 mảng ll và lll trong file Main đã phân tích ở trên, lần lượt 23 và 14 phần tử. Vậy từ đây rút ra flag dài 37 kí tự.

Tiếp theo là hàm sc:
```c
int __cdecl Java_xyz_scriptctf_Main_sc(int a1, int a2, unsigned __int16 a3, int a4)
{
  int v4; // esi
  int result; // eax
  int v6; // ebp
  int v7; // esi
  int v8; // ebp
  int v9; // eax
  int v10; // esi
  int v11; // ebp
  int *v12; // ecx
  int v13; // ebp
  bool v14; // zf
  int v15; // ebp
  int v16; // eax
  int v17; // eax
  int v18; // edi
  int v19; // eax
  int v20; // [esp+8h] [ebp-24h]
  int v21; // [esp+Ch] [ebp-20h]
  int v22; // [esp+14h] [ebp-18h]
  int v23; // [esp+18h] [ebp-14h]

  v4 = (*(int (__cdecl **)(int, int, void *, void *))(*(_DWORD *)a1 + 576))(a1, a2, &unk_2004, &unk_2000);
  result = (*(int (__cdecl **)(int, int, void *, void *))(*(_DWORD *)a1 + 576))(a1, a2, &unk_2003, &unk_2000);
  if ( v4 )
  {
    v6 = result;
    if ( result )
    {
      v7 = (*(int (__cdecl **)(int, int, int))(*(_DWORD *)a1 + 580))(a1, a2, v4);
      result = (*(int (__cdecl **)(int, int, int))(*(_DWORD *)a1 + 580))(a1, a2, v6);
      if ( v7 )
      {
        v8 = result;
        if ( result )
        {
          (*(void (__cdecl **)(int, int))(*(_DWORD *)a1 + 684))(a1, v7);
          (*(void (__cdecl **)(int, int))(*(_DWORD *)a1 + 684))(a1, v8);
          v9 = (*(int (__cdecl **)(int, int, _DWORD))(*(_DWORD *)a1 + 748))(a1, v7, 0);
          v23 = v7;
          v10 = v8;
          v11 = v9;
          result = (*(int (__cdecl **)(int, int, _DWORD))(*(_DWORD *)a1 + 748))(a1, v10, 0);
          v20 = v11;
          if ( v11 )
          {
            if ( result )
            {
              v22 = result;
              v12 = (int *)(result + 4 * a4 - 92);
              if ( a4 < 23 )
                v12 = (int *)(v11 + 4 * a4);
              if ( (a4 & 1) != 0 )
              {
                v21 = *v12;
                v15 = a1;
                v16 = (*(int (__cdecl **)(int, int, const char *, const char *))(*(_DWORD *)a1 + 452))(
                        a1,
                        a2,
                        "s2",
                        "(CI)I");
                if ( !v16
                  || (*(int (__cdecl **)(int, int, int, _DWORD, int))(*(_DWORD *)a1 + 516))(a1, a2, v16, a3, a4) == v21 )
                {
                  goto LABEL_18;
                }
              }
              else
              {
                v13 = *v12;
                v14 = sub_13B0(a3) == v13;
                v15 = a1;
                if ( v14 )
                {
LABEL_18:
                  (*(void (__cdecl **)(int, int, int, int))(*(_DWORD *)v15 + 780))(v15, v23, v20, 2);
                  return (*(int (__cdecl **)(int, int, int, int))(*(_DWORD *)v15 + 780))(v15, v10, v22, 2);
                }
              }
              puts("Incorrect!");
              v17 = (*(int (__cdecl **)(int, const char *))(*(_DWORD *)v15 + 24))(v15, "java/lang/System");
              if ( v17 )
              {
                v18 = v17;
                v19 = (*(int (__cdecl **)(int, int, const char *, const char *))(*(_DWORD *)v15 + 452))(
                        v15,
                        v17,
                        "exit",
                        "(I)V");
                if ( v19 )
                  (*(void (__cdecl **)(int, int, int, int))(*(_DWORD *)v15 + 564))(v15, v18, v19, 1);
              }
              goto LABEL_18;
            }
          }
        }
      }
    }
  }
  return result;
}
```
1 lần nữa ta lại đưa AI phân tích vì IDA decompile code java theo kiểu code C nên nhìn khá khó hiểu:

<img width="927" height="293" alt="image" src="https://github.com/user-attachments/assets/f1562054-71de-4edf-9b9a-78421fe0e87f" />

Hàm này sẽ check index, nếu index chẵn thì sẽ nhảy vào nhánh hàm s2 để check, còn nếu không thì sẽ nhảy vào nhánh hàm sub_13B0. Hàm s2 thì logic đã rõ như trong file main, còn hàm sub_13B0 thì ta nháy vào để xem: 

<img width="511" height="114" alt="image" src="https://github.com/user-attachments/assets/f94688e1-ea1d-483b-af0d-55507782557b" />

Với a1 là kí tự tại index a2.

Vậy đã rõ được logic của 2 hàm initialize() và sc(), việc còn lại là viết script để lấy flag

### Script

```python3
ll = [32, 92, 4, 104, 106, 76, 96, 113, 42, 65, 22, 43, 203, 84, 220, 98, 210, 71, 29, 123, 20, 125, 199]
lll = [76, 230, 117, 243, 84, 54, 103, 197, 104, 251, 83, 253, 128, 159]
expected = ll + lll
flag = [0]*37
for i in range(37):
    idx = (i*5 + 3) % 37
    if i%2 == 0:
        t = expected[i] ^ 0x5a
        u = t - 3*i
        s = (u ^ (i+19)) & 0xff
        flag[idx] = chr(s)
    else:
        t = expected[i] - 1
        u = t ^ 19
        s = u - (i % 7)*2
        flag[idx] = chr(s)
print(''.join(flag))
```        

## Plastic Shield 2
<img width="733" height="540" alt="image" src="https://github.com/user-attachments/assets/cc63505b-6bd0-49d0-bb8e-d7b0bada0e20" />

Bài này là bài nâng cao hơn so với bài đầu
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+0h] [rbp-350h] BYREF
  char v5[26]; // [rsp+100h] [rbp-250h] BYREF
  char nptr[2]; // [rsp+11Ah] [rbp-236h] BYREF
  char dest[4]; // [rsp+11Ch] [rbp-234h] BYREF
  char v8[157]; // [rsp+120h] [rbp-230h] BYREF
  char v9[19]; // [rsp+1BDh] [rbp-193h] BYREF
  char v10[64]; // [rsp+1D0h] [rbp-180h] BYREF
  char s[263]; // [rsp+210h] [rbp-140h] BYREF
  unsigned __int8 v12; // [rsp+317h] [rbp-39h]
  void *ptr; // [rsp+318h] [rbp-38h]
  char v14; // [rsp+327h] [rbp-29h]
  char *v15; // [rsp+328h] [rbp-28h]
  size_t v16; // [rsp+330h] [rbp-20h]
  size_t j; // [rsp+338h] [rbp-18h]
  size_t size; // [rsp+340h] [rbp-10h]
  unsigned __int64 i; // [rsp+348h] [rbp-8h]

  printf("Please enter the password: ");
  __isoc99_scanf("%255s", s);
  v16 = strlen(s);
  crypto_blake2b(v10, 64LL, s, v16);
  for ( i = 0LL; i <= 0x3F; ++i )
    sprintf(&v8[2 * i + 32], "%02x", (unsigned __int8)v10[i]);
  v9[3] = 0;
  v15 = "e2ea0d318af80079fb56db5674ca8c274c5fd0e92019acd01e89171bb889f6b1";
  memset(v8, 0, 0x20uLL);
  strncpy(dest, v9, 3uLL);
  dest[3] = 0;
  hex_to_bytes(dest, v8, 1LL);
  nptr[0] = v9[2];
  nptr[1] = 0;
  v14 = strtol(nptr, 0LL, 16);
  v8[1] = 16 * v14;
  memset(v5, 0, 0x10uLL);
  hex_to_bytes(dest, v5, 1LL);
  v5[1] = 16 * v14;
  size = strlen(v15) >> 1;
  ptr = malloc(size);
  hex_to_bytes(v15, ptr, size);
  AES_init_ctx_iv(v4, v8, v5);
  AES_CBC_decrypt_buffer(v4, ptr, size);
  v12 = *((_BYTE *)ptr + size - 1);
  if ( v12 <= 0x10u && v12 )
    size -= v12;
  printf("Decrypted text: ");
  for ( j = 0LL; j < size; ++j )
    putchar(*((unsigned __int8 *)ptr + j));
  putchar(10);
  free(ptr);
  return 0;
}
```
Bài này lấy cả password nhập vào rồi đem hash chứ không chỉ lấy 1 kí tự rồi đem hash như bài đầu, nhưng nó lại không lấy key và iv từ phần hash đấy. 2 buffer và iv chứa key được memset thành 0, rồi byte đầu của key và iv được lấy từ 2 digit hex của chuỗi v9, còn byte thứ 2 thì bằng 16*digit hex thứ 3 của chuỗi v9, các byte của buffer chứa key và iv thì được memset = 0 như lúc đầu.

Vậy ta chỉ cần brute-force từ 0x000 đến 0xfff, rồi tách digit hex thành 2 nửa: vd: fff thì tách thành ff và f, ff là byte đầu, còn f thì đem nhân với 16 để ra được byte thứ 2.

Với bài này, nó còn trick thêm ở phần cuối khi ta không biết decrypt theo AES-128 hay AES-256, ta sẽ thử cả 2 trường hợp, nếu 128 thì lấy key 16 byte, 256 thì lấy key 32 byte

### Script

```python3
import hashlib
from Crypto.Cipher import AES
v15 = "e2ea0d318af80079fb56db5674ca8c274c5fd0e92019acd01e89171bb889f6b1"
ciphertext = bytes.fromhex(v15)
for i in range(0x000,0xfff+1):
    h = f"{i:03x}"
    byte1 = h[0:2]
    byte2 = h[2:]
    key = bytearray(32)
    iv = bytearray(16)
    key[0],iv[0] = int(byte1, 16), int(byte1, 16)
    key[1],iv[1] = 16*int(byte2, 16), 16*int(byte2, 16)
    cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
    plaintext = cipher.decrypt(ciphertext)
    pad_len = plaintext[-1]
    if pad_len <= 0x10:
        plaintext = plaintext[:-pad_len]
    if plaintext and all(32 <= c < 127 for c in plaintext):
        print(plaintext.decode('utf-8'))
    else:
        key = key[:16]
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        plaintext = cipher.decrypt(ciphertext)
        pad_len = plaintext[-1]
        if pad_len <= 0x10:
            plaintext = plaintext[:-pad_len]
        if plaintext and all(32 <= c < 127 for c in plaintext):
            print(plaintext.decode('utf-8'))
```
