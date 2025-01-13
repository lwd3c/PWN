#include <stdio.h>
#include <stdlib.h>

struct pet
{
	char *name;
	void (*sound)();
} *pet_list[8];

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void human_sound(){
	puts("Hehehe");
	system("/bin/sh");
}

void menu()
{
	puts("--- MENU --------------");
	puts("1. Add pet to list");
	puts("2. Edit name of a pet");
	puts("3. Remove pet from list");
	puts("4. Play sound");
	puts("5. Exit");
	printf("> ");
}

void dog_sound()
{
	puts("Woof Woof");
}

void cat_sound()
{
	puts("Meows Meows");
}

void duck_sound()
{
	puts("Quacks Quacks");
}

void add_pet(int index)
{
	unsigned int type, size;

	pet_list[index] = malloc(sizeof(struct pet));

	puts("1. Dog");
	puts("2. Cat");
	puts("3. Duck");
	printf("> ");
	scanf("%u", &type);
	if (type==1)
		pet_list[index]->sound = dog_sound;
	else if (type==2)
		pet_list[index]->sound = cat_sound;
	else if (type==3)
		pet_list[index]->sound = duck_sound;

	printf("Name size: ");
	scanf("%u", &size);
	getchar();
	pet_list[index]->name = malloc(size);

	printf("Name: ");
	fgets(pet_list[index]->name, size, stdin);
}

void edit_pet(int index)
{
	unsigned int size;

	printf("Name size: ");
	scanf("%u", &size);
	getchar();
	pet_list[index]->name = malloc(size);

	printf("Name: ");
	fgets(pet_list[index]->name, size, stdin);
}

void remove_pet(int index)
{
	free(pet_list[index]->name);
	free(pet_list[index]);
}

void play_sound(int index){
	pet_list[index]->sound();
}

int main()
{
	int is_done = 0, option, index;

	init();

	while (!is_done)
	{
		menu();
		scanf("%d", &option);
		getchar();

		index = 8;
		printf("Index: ");
		scanf("%d", &index);
		getchar();

		switch(option)
		{
		case 1:
			add_pet(index);
			break;
		case 2:
			edit_pet(index);
			break;
		case 3:
			remove_pet(index);
			break;
		case 4:
			play_sound(index);
			break;
		case 5:
			is_done = 1;
			break;
		default:
			puts("Invalid choice!");
		}
	}
}