CC     = gcc
CFLAGS = -Wall -Wextra -O3
LDFLAGS = -fopenmp

BINDIR = bin
SRCDIR = src
OBJDIR = obj
INCLDIR = include

_BIN = dfa
BIN = $(addprefix $(BINDIR)/, $(_BIN)) 
SRC = $(wildcard $(SRCDIR)/*.c)
_OBJ = $(patsubst $(SRCDIR)/%.c, %.o, $(SRC))
OBJ = $(addprefix $(OBJDIR)/, $(_OBJ))


all:$(BIN)

$(BIN): $(BINDIR) $(OBJDIR) $(OBJ)
	$(CC) -o $(BIN) $(OBJ) $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@ -I$(INCLDIR)

.PHONY: clean

clean:
	rm -rf $(OBJDIR) $(BINDIR)
