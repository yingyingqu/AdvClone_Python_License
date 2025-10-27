文件功能说明：
----------------------------------------
（1）License_Generate_deviceID.py
Mac地址加密生成设备唯一标识，并保存到当前目录的device_id.txt文件下


（2）License_Generator.py
读取device_di.txt存储的设备标识，产生license文件license.lic


（3）License_Check.py
后面跟license文件路径，进行license验证


--------------------------------------------
打包exe:
-------------------------------------------------------------------
pyinstaller --onefile --windowed License_Generate_deviceID.py
pyinstaller --onefile --windowed License_Generator.py
pyinstaller --onefile --windowed License_Check.py

OR:

python -m PyInstaller --onefile --windowed License_Generate_deviceID.py
python -m PyInstaller --onefile --windowed License_Generator.py
python -m PyInstaller --onefile --windowed License_Check.py

