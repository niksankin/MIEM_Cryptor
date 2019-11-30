#include <libelf.h>
#include <gelf.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <error.h>

int add_name_to_str_table(Elf *e, char *name)
{
	Elf_Scn *scn = NULL;
	Elf_Data *data;
	GElf_Ehdr ehdr;

	gelf_getehdr(e, &ehdr);

	scn = elf_getscn(e, ehdr.e_shstrndx);

	data = elf_getdata(scn, NULL);

	if (!data)
	{
		printf(" elf_begin () failed: %s.", elf_errmsg(-1));
		return -1;
	}

	int new_table_size = data->d_size + strlen(name) + 1;
	int new_string_index = data->d_size;
	char *new_table = calloc(new_table_size, sizeof(char));

	strcpy(data->d_buf + 1, name);

	data->d_size = new_table_size;

	return new_string_index;
}

unsigned char lea_rip[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x8D, 0x5, 0x0, 0x0, 0x0, 0x0 };
unsigned char mov_rax_64[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mov_rax_32[] = { 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00};
unsigned char push_rax = 0x50;

#define PREPARE_MOV_X64(num) memcpy(mov_rax_64 + 2, &num, sizeof(uint64_t))
#define PREPARE_MOV_X32(num) memcpy(mov_rax_32 + 3, &num, sizeof(uint32_t))
#define PAYLOAD_MAX_SIZE sizeof(lea_rip) + 2*sizeof(mov_rax_64) + 2*sizeof(push_rax)

int main(int argc, char* argv[])
{
	int fd;
	int new_fd;
	Elf *e;
	Elf *new_e;
	Elf_Scn *scn = NULL;
	Elf_Data *data = NULL;
	Elf64_Shdr *shdr = NULL;
	Elf_Data *str_table_data = NULL;
	Elf_Scn *str_table_scn = NULL;
	Elf64_Shdr *str_table_shdr = NULL;
	
	int ret = 0;

	fd = open(argv[1], O_RDWR);

	if (fd == -1)
		perror("some shiett occured: ");

	elf_version(EV_CURRENT);

	e = elf_begin(fd, ELF_C_RDWR, NULL);

	//elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);

	if (!e)
		printf(" elf_begin () failed: %s.", elf_errmsg(-1));

	Elf64_Ehdr *ehdr = elf64_getehdr(e);

	//получим данные секции строк
	str_table_scn = elf_getscn(e, ehdr->e_shstrndx);

	str_table_data = elf_getdata(str_table_scn, str_table_data);

	str_table_shdr = elf64_getshdr(str_table_scn);

	//добавляем имя новой секции в таблицу имен секций

	/*char *name = ".STUB";

	if (!str_table_data)
	{
		printf(" elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}

	int new_table_size = str_table_data->d_size + strlen(name) + 1;
	int new_string_index = str_table_data->d_size;

	char *new_table = calloc(new_table_size, sizeof(char));

	memcpy(new_table, str_table_data->d_buf, str_table_data->d_size);

	strcpy(new_table + new_string_index, name);

	str_table_data->d_size = new_table_size;

	str_table_data->d_buf = new_table;

	str_table_shdr = elf64_getshdr(str_table_scn);

	str_table_shdr->sh_size = new_table_size;

	(void)elf_flagshdr(str_table_scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagscn(str_table_scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagdata(str_table_data, ELF_C_SET, ELF_F_DIRTY);*/

	new_fd = open("modified", O_WRONLY | O_CREAT, 0777);

	new_e = elf_begin(new_fd, ELF_C_WRITE, NULL);

	elf_flagelf(new_e, ELF_C_SET, ELF_F_LAYOUT);

	Elf64_Ehdr *new_ehdr = elf64_newehdr(new_e);

	*new_ehdr = *ehdr;

	Elf64_Phdr *new_phdr;
	Elf64_Phdr *old_phdr;

	new_phdr = elf64_newphdr(new_e, ehdr->e_phnum);
	old_phdr = elf64_getphdr(e);

	Elf_Scn *old_scn = NULL;
	Elf_Data *old_data;
	Elf64_Shdr *old_shdr;
	Elf_Scn *new_scn = NULL;
	Elf_Data *new_data;
	Elf64_Shdr *new_shdr;

	int total_added_offset = 0;
	Elf64_Off stub_file_offset = 0;
	Elf64_Off stub_offset = 0;

	unsigned char *buf;

	unsigned int buf_size;
	Elf64_Off entry_offset;

	//откроем файл со стабом и скопируем .text в буффер для секции
	int stub_elf = open("stub_linux_amd64", O_RDWR);

	Elf *stub_e = elf_begin(stub_elf, ELF_C_READ, NULL);
	Elf64_Ehdr *stub_ehdr = elf64_getehdr(stub_e);
	
	Elf_Data *str_stub_table_data = NULL;
	Elf_Scn *str_stub_table_scn = NULL;
	Elf64_Shdr *str_stub_table_shdr = NULL;

	str_stub_table_scn = elf_getscn(stub_e, stub_ehdr->e_shstrndx);

	str_stub_table_data = elf_getdata(str_stub_table_scn, str_stub_table_data);

	str_stub_table_shdr = elf64_getshdr(str_stub_table_scn);

	scn = NULL;

	while ((scn = elf_nextscn(stub_e, scn)) != NULL)
	{
		shdr = elf64_getshdr(scn);

		char* section_name = (char*)(str_stub_table_data->d_buf + shdr->sh_name);

		if (!strcmp(section_name, ".text"))
		{
			data = NULL;
			data = elf_getdata(scn, data);

			buf_size = data->d_size + PAYLOAD_MAX_SIZE;
			buf = calloc(buf_size, sizeof(unsigned char));

			break;
		}
	}

	//копируем все секции и вставляем новую со стабом

	while ((old_scn = elf_nextscn(e, old_scn)) != NULL)
	{
		old_shdr = elf64_getshdr(old_scn);

		char* section_name = (char*)(str_table_data->d_buf + old_shdr->sh_name);

		old_data = NULL;
		old_data = elf_getdata(old_scn, old_data);

		new_scn = elf_newscn(new_e);

		new_data = elf_newdata(new_scn);

		*new_data = *old_data;

		if (!strcmp(section_name, ".data"))
		{
			new_shdr = elf64_getshdr(new_scn);

			*new_shdr = *old_shdr;

			if (new_shdr->sh_addr != 0)
				new_shdr->sh_addr -= new_shdr->sh_offset - 1;

			new_shdr->sh_offset += total_added_offset;

			size_t data_offset = new_shdr->sh_offset;
			size_t data_size = new_shdr->sh_size;
			size_t data_vaddr = new_shdr->sh_addr;

			new_scn = elf_newscn(new_e);

			new_data = elf_newdata(new_scn);

			new_data->d_align = 1;
			new_data->d_off = 0LL;
			new_data->d_buf = buf;
			new_data->d_type = ELF_T_BYTE;
			new_data->d_size = buf_size;
			new_data->d_version = EV_CURRENT;

			new_shdr = elf64_getshdr(new_scn);
			new_shdr->sh_name = 1;
			new_shdr->sh_type = SHT_PROGBITS;
			new_shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
			new_shdr->sh_size = buf_size;
			new_shdr->sh_offset = data_offset + data_size;
			new_shdr->sh_addr = data_vaddr;	//just base of addr
			new_shdr->sh_addralign = 0;

			total_added_offset += new_shdr->sh_size;

			stub_file_offset = new_shdr->sh_offset;
			stub_offset = stub_file_offset + new_shdr->sh_addr - 1;
		}
		else
		{
			new_shdr = elf64_getshdr(new_scn);

			*new_shdr = *old_shdr;

			if (new_shdr->sh_addr != 0)
				new_shdr->sh_addr -= new_shdr->sh_offset - 1;

			new_shdr->sh_offset += total_added_offset;
		}

		if (!strcmp(section_name, ".shstrtab"))
			new_ehdr->e_shstrndx = elf_ndxscn(new_scn);

		if (!strcmp(section_name, ".text"))
		{
			entry_offset = old_shdr->sh_addr;
		}
	}

	new_ehdr->e_shoff += total_added_offset;

	int shellcode_offset = 0;

	memcpy(buf, lea_rip, sizeof(lea_rip));

	shellcode_offset += sizeof(lea_rip);

	/*if (entry_offset > 0xffffffff)
	{
		PREPARE_MOV_X64(entry_offset);
		memcpy(buf + shellcode_offset, mov_rax_64, sizeof(mov_rax_64));
		shellcode_offset += sizeof(mov_rax_64);
	}
	else
	{
		PREPARE_MOV_X32(entry_offset);
		memcpy(buf + shellcode_offset, mov_rax_32, sizeof(mov_rax_32));
		shellcode_offset += sizeof(mov_rax_32);
	}
		
	memcpy(buf + shellcode_offset, &push_rax, sizeof(push_rax));

	shellcode_offset += sizeof(push_rax);
	
	if (stub_offset > 0xffffffff)
	{
		PREPARE_MOV_X64(stub_offset);
		memcpy(buf + shellcode_offset, mov_rax_64, sizeof(mov_rax_64));
		shellcode_offset += sizeof(mov_rax_64);
	}
	else
	{
		PREPARE_MOV_X32(stub_offset);
		memcpy(buf + shellcode_offset, mov_rax_32, sizeof(mov_rax_32));
		shellcode_offset += sizeof(mov_rax_32);
	}

	memcpy(buf + shellcode_offset, &push_rax, sizeof(push_rax));

	shellcode_offset += sizeof(push_rax);*/

	memcpy(buf + shellcode_offset, data->d_buf, data->d_size);	

	ret = elf_update(new_e, ELF_C_NULL);

	if (ret == -1)
	{
		printf("1 elf_begin () failed: %s.", elf_errmsg(-1));
		//goto exit;
	}

	new_ehdr->e_entry = stub_offset;

	new_scn = NULL;

	Elf_Data *str_new_table_data = NULL;
	Elf_Scn *str_new_table_scn = NULL;
	Elf64_Shdr *str_new_table_shdr = NULL;

	str_new_table_scn = elf_getscn(new_e, new_ehdr->e_shstrndx);

	str_new_table_data = elf_getdata(str_new_table_scn, str_new_table_data);

	str_new_table_shdr = elf64_getshdr(str_new_table_scn);

	while ((new_scn = elf_nextscn(new_e, new_scn)) != NULL)
	{
		new_shdr = elf64_getshdr(new_scn);

		char* section_name = (char*)(str_new_table_data->d_buf + new_shdr->sh_name);

		if (new_shdr->sh_addr != 0)
			new_shdr->sh_addr += new_shdr->sh_offset - 1;
	}

	for (int i = 0; i < ehdr->e_phnum; ++i)
	{
		new_phdr[i] = old_phdr[i];

		if (new_phdr[i].p_type == PT_LOAD && new_phdr[i].p_flags & PF_W)
			new_phdr[i].p_flags |= PF_X;

		if (new_phdr[i].p_type == PT_LOAD && new_phdr[i].p_flags & PF_X)
			new_phdr[i].p_flags |= PF_W;

		//если изменённая секция внутри
		if (new_phdr[i].p_offset <= stub_file_offset && new_phdr[i].p_offset + new_phdr[i].p_filesz >= stub_file_offset)
		{
			new_phdr[i].p_filesz += total_added_offset;
			new_phdr[i].p_memsz += total_added_offset;
		}
		//если сегмент следует за изменённой секцией
		else if (new_phdr[i].p_offset > stub_file_offset)
		{
			new_phdr[i].p_offset += total_added_offset;
			new_phdr[i].p_vaddr += total_added_offset;
			new_phdr[i].p_paddr += total_added_offset;
		}
	}

	ret = elf_update(new_e, ELF_C_WRITE);

	(void)elf_end(new_e);
	(void)close(new_fd);

	elf_end(stub_e);
	close(stub_elf);

	/*ret = elf_update(e, ELF_C_NULL);

	if (ret == -1)
	{
		printf("1 elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}

	//printf("Add section %s\n", elf_strptr(e, ehdr.e_shstrndx, shdr.sh_name));

	(void)elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagehdr(e, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	ret = elf_update(e, ELF_C_WRITE);

	if (ret == -1)
	{
		printf("2 elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}*/

exit:
	elf_end(e);
	close(fd);
}