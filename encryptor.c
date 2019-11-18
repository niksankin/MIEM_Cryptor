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
	Elf *e;
	Elf_Scn *scn = NULL;
	Elf_Data *data = NULL;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	GElf_Shdr shdr;
	int ret;

	fd = open(argv[1], O_RDWR);

	if (fd == -1)
		perror("some shiett occured: ");

	elf_version(EV_CURRENT);

	e = elf_begin(fd, ELF_C_RDWR, NULL);

	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	if (!e)
		printf(" elf_begin () failed: %s.", elf_errmsg(-1));

	gelf_getehdr(e, &ehdr);
	
	//добавляем имя новой секции в таблицу имен секций

	scn = elf_getscn(e, ehdr.e_shstrndx);

	char *name = ".STUB";

	data = elf_getdata(scn, data);

	if (!data)
	{
		printf(" elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}

	//как будто бы за счет какой-то секции все неправильно выделяется...
	int new_table_size = data->d_size + strlen(name) + 1;
	int new_string_index = data->d_size;

	char *new_table = calloc(new_table_size, sizeof(char));

	memcpy(new_table, data->d_buf, data->d_size);

	strcpy(new_table + new_string_index, name);

	data->d_size = new_table_size;
	
	//memcpy(data->d_buf, new_table, new_table_size);

	data->d_buf = new_table;

	//добавляем саму секцию

	/*scn = elf_newscn(e);

	data = elf_newdata(scn);

	unsigned char *buf = {0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

	data->d_align = 1;
	data->d_buf = buf;
	data->d_off = 0;
	data->d_size = sizeof(buf);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	gelf_getshdr(scn, &shdr);

	shdr.sh_name = new_string_index;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	shdr.sh_entsize = 0;
	shdr.sh_size = sizeof(buf);
	shdr.sh_addralign = 16;
	shdr.sh_offset = 15071;
	shdr.sh_addr = ;*/

	ret = elf_update(e, ELF_C_NULL);

	if (ret == -1)
	{
		printf("1 elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}

	//printf("Add section %s\n", elf_strptr(e, ehdr.e_shstrndx, shdr.sh_name));

	ret = elf_update(e, ELF_C_WRITE);

	if (ret == -1)
	{
		printf("2 elf_begin () failed: %s.", elf_errmsg(-1));
		goto exit;
	}
	
exit:
	elf_end(e);
	close(fd);
}