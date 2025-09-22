pdf:
	mkdir -p ./build
	(cd ./build; latexmk -shell-escape -pdf ../main.tex)

clean:
	rm -rf build

preview: pdf
	(cd ./build; latexmk -pdf -pvc -shell-escape ../main.tex)

monitor:
	while inotifywait -e close_write main.tex; do make preview; done
