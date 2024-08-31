项目名称：DLL 注入工具集说明文档
一、概述
本代码提供了多种不同的方法来实现将 DLL 注入到目标进程中，包括 注册表注入、APC（Asynchronous Procedure Call）注入、远程线程注入、RtlCreateUserThread 注入和窗口钩子注入。这些方法可用于在特定场景下将自定义的 DLL 加载到目标进程的地址空间中.
二、包含的命名空间及功能
APCTargetedInjection命名空间
inject_dll_by_apc函数：通过将指定的 DLL 路径写入目标进程的内存空间，然后利用 APC（异步过程调用）机制将加载 DLL 的函数排队到目标进程的线程中，实现 DLL 注入。
RemoteThreadInjection命名空间
inject_dll_to_process函数：通过在目标进程中创建远程线程，该线程的起始地址为加载指定 DLL 的函数，从而实现将 DLL 注入到目标进程中。
RtlCreateThreadInjection命名空间
inject_dll_by_rtl_create_user_thread函数：使用 Windows 内核函数RtlCreateUserThread在目标进程中创建线程，该线程用于加载指定的 DLL，实现 DLL 注入。
WindowsHookInjection命名空间
inject_dll_by_set_windows_hook_ex函数：通过设置窗口钩子，加载包含钩子函数的 DLL。当特定的窗口事件发生时，系统会调用钩子函数，从而实现 DLL 注入。
RegistryInjection命名空间
功能说明：通过修改注册表特定键值，使得系统在特定情况下自动加载指定的 DLL 到目标进程中。具体来说，可能是利用系统在加载某些关键模块时会检查特定注册表键值的特性。
例如，可能修改与系统启动或特定模块加载相关的注册表项，将 DLL 的路径添加到其中。这样，当系统满足特定条件时，会自动加载该 DLL 到目标进程的地址空间中。

三、主要函数说明

write_to_remote_process_memory函数
功能：将数据写入到指定进程的内存空间中。
参数：
h_process：目标进程的句柄。
remote_mem：目标进程中的内存地址。
data：要写入的数据。
size：数据的大小。
返回值：如果写入成功返回true，否则返回false。
get_all_threads_of_process函数
功能：获取指定进程的所有线程句柄。
参数：
process_id：目标进程的 ID。
thread_handles：用于存储获取到的线程句柄的向量。
返回值：如果成功找到至少一个线程，返回true，否则返回false。
get_load_library_address函数
功能：获取kernel32.dll中LoadLibraryA函数的地址，该函数用于加载 DLL。
返回值：LoadLibraryA函数的起始地址，如果获取失败返回nullptr。
四、使用方法
编译并运行包含此代码的程序。
可以通过命令行参数或交互式输入来选择注入方法、目标进程 ID 和 DLL 路径。如果使用窗口钩子注入，还可以指定目标线程 ID（可选）。
程序将根据选择的注入方法调用相应的命名空间中的函数来尝试将 DLL 注入到目标进程中。
如果注入成功，程序会输出相应的成功信息；如果注入失败，会输出错误信息。
