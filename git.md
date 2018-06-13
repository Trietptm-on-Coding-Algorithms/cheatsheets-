# remove folder from repo
```
git clone https://github.com/rebellionil/rebel-framework
cd rebel-framework/modules/web/
git rm -rf --cached wascan_mod/
git commit -m "remove buggy web scanner"
git push  origin master
```
