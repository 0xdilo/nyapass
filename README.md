# nyapass

smol password manager tui :3

```
    /\_____/\
   /  o   o  \
  ( ==  ^  == )
   )         (
  (           )
 ( (  )   (  ) )
 (__(__)___(__)__)
```

## features

- AES-256-GCM encryption
- Argon2id key derivation
- categories & entries
- global search across all entries
- password generator (16-32 chars)
- wayland clipboard support (wl-copy)
- vim-style navigation (hjkl)

## install

```bash
cargo install --git https://github.com/0xdilo/nyapass
```

or with UPX compression:

```bash
git clone https://github.com/0xdilo/nyapass
cd nyapass
make install
```

## usage

```bash
nyapass
```

vault stored at `~/.config/nyapass/vault.enc`

### keybinds

**categories**
- `a` add category
- `d` delete category
- `/` global search
- `enter` open category
- `ctrl+s` save
- `q` quit

**entries**
- `a` add entry
- `e` edit entry
- `d` delete entry
- `c` copy password
- `u` copy username
- `p` show/hide password
- `/` search in category
- `h` go back

**forms**
- `tab` next field
- `ctrl+g` generate password
- `F2` or `enter` (on notes) save
- `esc` cancel

## dependencies

- wl-copy (wayland) or xclip (x11) for clipboard
