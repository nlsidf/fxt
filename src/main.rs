use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use thiserror::Error;

const EOCD_SIG: u32 = 0x06054b50;
const ZIP64_LOCATOR_SIG: u32 = 0x07064b50;
// const ZIP64_EOCD_SIG: u32 = 0x06064b50;
const CENTRAL_DIR_SIG: u32 = 0x02014b50;
const ZIP64_EXT_TAG: u16 = 0x0001;
const CENTRAL_DIR_FIXED_SIZE: u64 = 46;

#[derive(Error, Debug)]
enum ZipFixError {
    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("找不到ZIP尾部结构")]
    EocdNotFound,
    #[error("ZIP格式错误")]
    BadZip,
}
type Result<T> = std::result::Result<T, ZipFixError>;

fn read_u16(f: &mut File) -> Result<u16> {
    let mut b = [0; 2];
    f.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32(f: &mut File) -> Result<u32> {
    let mut b = [0; 4];
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(f: &mut File) -> Result<u64> {
    let mut b = [0; 8];
    f.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("用法: {} <待修复ZIP文件>", args[0]);
        std::process::exit(1);
    }
    let path = &args[1];
    if !Path::new(path).exists() {
        eprintln!("文件不存在: {}", path);
        std::process::exit(1);
    }

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    fix_zip_offsets(&mut f)?;
    println!("修复完成！文件: {}", path);
    Ok(())
}

fn fix_zip_offsets(f: &mut File) -> Result<()> {
    let file_size = f.metadata()?.len();
    let (is_zip64, tail_pos) = find_tail_struct(f, file_size)?;
    if is_zip64 {
        fix_zip64(f, tail_pos)?;
    } else {
        fix_regular(f, tail_pos)?;
    }
    Ok(())
}

fn find_tail_struct(f: &mut File, file_size: u64) -> Result<(bool, u64)> {
    let search_range = 0x10000;
    let search_start = if file_size > search_range {
        file_size - search_range
    } else {
        0
    };
    let buf_len = (file_size - search_start) as usize;
    let mut buf = vec![0; buf_len];
    f.seek(SeekFrom::Start(search_start))?;
    f.read_exact(&mut buf)?;
    for i in (0..buf_len - 3).rev() {
        let sig = u32::from_le_bytes([buf[i], buf[i+1], buf[i+2], buf[i+3]]);
        if sig == ZIP64_LOCATOR_SIG {
            return Ok((true, search_start + i as u64));
        } else if sig == EOCD_SIG {
            return Ok((false, search_start + i as u64));
        }
    }
    Err(ZipFixError::EocdNotFound)
}

fn fix_regular(f: &mut File, eocd_pos: u64) -> Result<()> {
    f.seek(SeekFrom::Start(eocd_pos))?;
    let _sig = read_u32(f)?;
    let _disk_num = read_u16(f)?;
    let _cd_disk = read_u16(f)?;
    let _disk_ent = read_u16(f)?;
    let total_ent = read_u16(f)?;
    let cd_size = read_u32(f)?;
    let old_cd_offset = read_u32(f)?;
    let _comment_len = read_u16(f)?;

    let cd_actual_start = eocd_pos - cd_size as u64;
    let prefix_len = cd_actual_start.saturating_sub(old_cd_offset as u64);
    if prefix_len <= 0 {
        println!("未检测到前置数据，无需修复");
        return Ok(());
    }

    fix_central_dir(f, cd_actual_start, total_ent as u64, prefix_len, false)?;

    f.seek(SeekFrom::Start(eocd_pos + 16))?;
    f.write_all(&cd_actual_start.to_le_bytes())?;
    Ok(())
}

fn fix_zip64(f: &mut File, locator_pos: u64) -> Result<()> {
    f.seek(SeekFrom::Start(locator_pos))?;
    let _sig = read_u32(f)?; // 签名已验证
    let _disk_num = read_u32(f)?;
    let eocd_pos = read_u64(f)?;
    let _total_disks = read_u32(f)?;

    f.seek(SeekFrom::Start(eocd_pos))?;
    let _sig = read_u32(f)?; // 签名已验证
    let _size = read_u64(f)?;
    let _ver_made = read_u16(f)?;
    let _ver_need = read_u16(f)?;
    let _disk_num = read_u32(f)?;
    let _cd_disk = read_u32(f)?; // 无用
    let _disk_ent = read_u64(f)?;
    let total_ent = read_u64(f)?;
    let cd_size = read_u64(f)?; // 中央目录大小（关键）
    let old_cd_offset = read_u64(f)?; // 原始中央目录偏移（关键）

    let cd_actual_start = eocd_pos - cd_size;
    let prefix_len = cd_actual_start.saturating_sub(old_cd_offset);
    if prefix_len <= 0 {
        println!("未检测到前置数据，无需修复");
        return Ok(());
    }

    fix_central_dir(f, cd_actual_start, total_ent, prefix_len, true)?;

    f.seek(SeekFrom::Start(eocd_pos + 48))?;
    f.write_all(&cd_actual_start.to_le_bytes())?;

    let new_eocd_offset = eocd_pos + prefix_len;
    f.seek(SeekFrom::Start(locator_pos + 8))?;
    f.write_all(&new_eocd_offset.to_le_bytes())?;
    Ok(())
}

fn fix_central_dir(
    f: &mut File,
    cd_start: u64,
    entry_count: u64,
    prefix_len: u64,
    is_zip64: bool,
) -> Result<()> {
    let mut curr_pos = cd_start;
    for _entry_idx in 0..entry_count {
        f.seek(SeekFrom::Start(curr_pos))?;
        if read_u32(f)? != CENTRAL_DIR_SIG {
            return Err(ZipFixError::BadZip);
        }

        let local_off_pos = curr_pos + 42;
        f.seek(SeekFrom::Start(local_off_pos))?;
        let old_off = read_u32(f)?;
        let new_off = (old_off as u64 + prefix_len) as u32;
        f.seek(SeekFrom::Start(local_off_pos))?;
        f.write_all(&new_off.to_le_bytes())?;

        if is_zip64 {
            f.seek(SeekFrom::Start(curr_pos + 28))?;
            let fname_len = read_u16(f)? as u64;
            let extra_len = read_u16(f)? as u64;
            let extra_pos = curr_pos + CENTRAL_DIR_FIXED_SIZE + fname_len;

            if extra_len > 0 {
                f.seek(SeekFrom::Start(extra_pos))?;
                let mut extra_buf = vec![0; extra_len as usize];
                f.read_exact(&mut extra_buf)?;

                let mut idx = 0;
                while idx + 4 <= extra_buf.len() {
                    let tag = u16::from_le_bytes([extra_buf[idx], extra_buf[idx + 1]]);
                    let field_size = u16::from_le_bytes([extra_buf[idx + 2], extra_buf[idx + 3]]) as usize;
                    idx += 4;

                    if tag == ZIP64_EXT_TAG && idx + field_size <= extra_buf.len() {
                        let zip64_off_offset = 16;
                        if field_size >= zip64_off_offset + 8 {
                            let old_off64 = u64::from_le_bytes(
                                extra_buf[idx + zip64_off_offset..idx + zip64_off_offset + 8]
                                    .try_into()
                                    .unwrap()
                            );
                            let new_off64 = old_off64 + prefix_len;

                            let write_pos = extra_pos + idx as u64 + zip64_off_offset as u64;
                            f.seek(SeekFrom::Start(write_pos))?;
                            f.write_all(&new_off64.to_le_bytes())?;
                        }
                        idx += field_size;
                    }
                }
            }
        }

        f.seek(SeekFrom::Start(curr_pos + 28))?;
        let fname_len = read_u16(f)? as u64;
        let extra_len = read_u16(f)? as u64;
        curr_pos += CENTRAL_DIR_FIXED_SIZE + fname_len + extra_len;

        if curr_pos > f.metadata()?.len() {
            return Err(ZipFixError::BadZip);
        }
    }
    Ok(())
}
