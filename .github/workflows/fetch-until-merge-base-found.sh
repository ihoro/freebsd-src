#!/bin/sh

main_depth=20
target_depth=20

until git merge-base origin/main $GITHUB_REF_NAME
do
  echo "Fetching main with depth=$main_depth..."
  git fetch --no-tags --no-recurse-submodules --depth=$main_depth origin main
  main_depth=$((main_depth*4))

  echo "Fetching target with depth=$target_depth..."
  git fetch --no-tags --no-recurse-submodules --depth=$target_depth origin $GITHUB_REF_NAME
  target_depth=$((target_depth+20))
done
