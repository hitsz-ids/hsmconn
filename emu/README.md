# 密码机模拟器

## 概述
密码机模拟器为一个C++开发库，其提供了对《GM/T 0018 密码设备应用接口规范》的软件实现，方便应用系统通过集成模拟器接口库的方式，无须依赖硬件密码机硬件设备，即可完成开发、测试阶段的闭环。

## 功能
- 符合《GM/T 0018 密码设备应用接口规范》，提供软件实现的SDF接口
- 提供`hsm-emu-tool`管理工具，方便开发人员管理生成密钥
- 支持被`HSMC`调度，并由`HSMC`统一为上层应用提供接口调用

## 编译&安装
密码机模拟器由`HSMC`库默认自带，在编译、安装`HSMC`库时将自动编译、安装

## 管理密钥
当前，密码机模拟器使用yaml配置文件来管理密钥，yaml配置文件可以使用自带的`hsm-emu-tool`自动生成，该工具默认安装在/usr/local/bin目录下，使用方法如下：

```shell
/usr/local/bin/hsm-emu-tool -h
/usr/local/bin/hsm-emu-tool - An utility tool for HSM-Emulator
Usage: /usr/local/bin/hsm-emu-tool [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit

Subcommands:
  genkek                      generate kek
```

### 生成KEK

运行如下：
```shell
/usr/local/bin/hsm-emu-tool genkek --config hsm-emu-config.yaml --index 1 20
```

运行成功后，将在hsm-emu-config.yaml文件中（若该文件不存在，则需要手动创建），自动生成索引范围1~10的KEK，如下：

```yaml showLineNumbers title="hsm-emu-config.yaml"
kek:
  1: kE8D+6Y4ATD9tA43waDqrA==
  2: m9L8ktbKtTScitcwxQPm5A==
  3: uMCyLdVK4z80xiqMo2Th2A==
  4: y5s9V1AX/fhtc7RlrvVg6w==
  5: upzpIVtVrru61ag1CbbT0w==
  6: XXqmmGS3dCnVlbXJXZ51jg==
  7: H1dr0RT6BjZ+EvdMUHeVxg==
  8: oMb670wyAsw/Tc/OglBgXQ==
  9: cJd8BD3lVwtbi5BbdKrHZA==
  10: +jv/xO0zM2Z9tD91XFx+KQ==
```

> [!NOTE]
> 当前密码机模拟器主要用于开发、调试使用，不建议使用在生成环境下。另外，模拟器的配置文件中的kek也是明文存储，在生产使用明文密钥存储存在安全风险。**