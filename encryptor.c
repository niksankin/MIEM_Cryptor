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
	int ret;

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
	(void)elf_flagdata(str_table_data, ELF_C_SET, ELF_F_DIRTY);

	//добавляем саму секцию

	scn = elf_newscn(e);

	data = elf_newdata(scn);

	unsigned char buf[] = {0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

	data->d_align = 1;
	data->d_off = 0LL;
	data->d_buf = buf;
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof(buf);
	data->d_version = EV_CURRENT;

	shdr = elf64_getshdr(scn);
	shdr->sh_name = new_string_index;
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	shdr->sh_size = sizeof(buf);
	
	//добавляем в существующий загружаемый сегмент
	//TODO: автоматическое вычисление нужного размера для сегмента

	Elf64_Phdr *phdr = elf64_getphdr(e);

	for (int i = 0; i < ehdr->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
			shdr->sh_addr = phdr[i].p_vaddr + phdr[i].p_memsz;
			shdr->sh_offset = phdr[i].p_offset + phdr[i].p_filesz;

			phdr[i].p_filesz += shdr->sh_size;
			phdr[i].p_memsz += shdr->sh_size;

			break;
		}
	}*/

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
	
	char* new_sec_data = NULL;

	int incr_size = 0x00;
	int total_added_offset = 0;
	int32_t text_file_offset = 0;
	int32_t text_offset = 0;

	unsigned char buf[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

	//int evil_elf = open("", O_RDWR);

	while ((old_scn = elf_nextscn(e, old_scn)) != NULL)
	{
		old_shdr = elf64_getshdr(old_scn);

		char* section_name = (char*)(str_table_data->d_buf + old_shdr->sh_name);
		
		old_data = NULL;
		old_data = elf_getdata(old_scn, old_data);

		new_scn = elf_newscn(new_e);

		new_data = elf_newdata(new_scn);

		*new_data = *old_data;

		//new_data->d_off = 0LL;

		/*if (!strcmp(section_name, ".text"))
		{
			new_sec_data = realloc(new_sec_data, old_data->d_size + incr_size);
			memcpy(new_sec_data, old_data->d_buf, old_data->d_size);
			memset(new_sec_data + old_data->d_size, 0x99, incr_size);

			new_data->d_buf = new_sec_data;
			new_data->d_size = old_data->d_size + incr_size;

			new_shdr = elf64_getshdr(new_scn);

			*new_shdr = *old_shdr;

			if (new_shdr->sh_addr != 0)
				new_shdr->sh_addr -= new_shdr->sh_offset - 1;

			//new_shdr->sh_offset = 0LL;
			new_shdr->sh_size += incr_size;

			total_added_offset += incr_size;

			text_offset = new_shdr->sh_offset;
		}
		else*/ if (!strcmp(section_name, ".bss"))
		{
			new_shdr = elf64_getshdr(new_scn);

			*new_shdr = *old_shdr;

			if (new_shdr->sh_addr != 0)
				new_shdr->sh_addr -= new_shdr->sh_offset - 1;

			new_shdr->sh_offset += total_added_offset;

			size_t bss_offset = new_shdr->sh_offset;
			size_t bss_size = new_shdr->sh_size;
			size_t bss_vaddr = new_shdr->sh_addr;

			new_scn = elf_newscn(new_e);

			new_data = elf_newdata(new_scn);

			new_data->d_align = 1;
			new_data->d_off = 0LL;
			new_data->d_buf = buf;
			new_data->d_type = ELF_T_BYTE;
			new_data->d_size = sizeof(buf);
			new_data->d_version = EV_CURRENT;

			new_shdr = elf64_getshdr(new_scn);
			new_shdr->sh_name = 1;
			new_shdr->sh_type = SHT_PROGBITS;
			new_shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
			new_shdr->sh_size = sizeof(buf);
			new_shdr->sh_offset = bss_offset;
			new_shdr->sh_addr = bss_vaddr;
			new_shdr->sh_addralign = 1;

			total_added_offset += new_shdr->sh_size;

			text_file_offset = new_shdr->sh_offset;
			text_offset = text_file_offset + new_shdr->sh_addr - 1;
		}
		else
		{
			new_shdr = elf64_getshdr(new_scn);

			*new_shdr = *old_shdr;

			if (new_shdr->sh_addr != 0)
				new_shdr->sh_addr -= new_shdr->sh_offset - 1;
			 
			//if(strcmp(section_name, ".shstrtab") && strcmp(section_name, ".symtab") && strcmp(section_name, ".strtab"))
				new_shdr->sh_offset += total_added_offset;

			//new_shdr->sh_offset = 0LL;
		}

		if(!strcmp(section_name, ".shstrtab"))
			new_ehdr->e_shstrndx = elf_ndxscn(new_scn);
	}

	new_ehdr->e_shoff += total_added_offset;

	ret = elf_update(new_e, ELF_C_NULL);

	//new_ehdr->e_entry = text_offset;

	new_scn = NULL;
	while ((new_scn = elf_nextscn(new_e, new_scn)) != NULL)
	{
		new_shdr = elf64_getshdr(new_scn);

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
		if (new_phdr[i].p_offset <= text_file_offset && new_phdr[i].p_offset + new_phdr[i].p_filesz >= text_file_offset)
		{
			new_phdr[i].p_filesz += total_added_offset;
			new_phdr[i].p_memsz += total_added_offset;
		}
		//если сегмент следует за изменённой секцией
		else if (new_phdr[i].p_offset > text_file_offset)
		{
			new_phdr[i].p_offset += total_added_offset;
			new_phdr[i].p_vaddr += total_added_offset;
			new_phdr[i].p_paddr += total_added_offset;
		}
	}
	ret = elf_update(new_e, ELF_C_WRITE);

	(void)elf_end(new_e);
	(void)close(new_fd);

	FILE *entry_fd = fopen("modified", "rb+");

	fseek(entry_fd, 24, SEEK_SET);
	fwrite(&text_offset, 1, sizeof(text_offset), entry_fd);
	fclose(entry_fd);

	   
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