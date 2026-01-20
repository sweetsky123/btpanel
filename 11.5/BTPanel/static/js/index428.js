import{ao as i,D as n,_ as p}from"./utils-lib.js?v=1768643427";import{c as u,r as c,x as d,O as f,z as T,R as b,e as o,d as a}from"./base-lib.js?v=1768643427";import"./__commonjsHelpers__.js?v=1768643427";const v=u({__name:"index",setup(x){const r=a(()=>n(()=>import("./auto-complete.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)),l=a(()=>n(()=>import("./terminal-theme.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)),e=c("smartTips"),s=[{label:"智能提示",lazy:!0,name:"smartTips",render:()=>o(r,null,null)},{label:"终端主题",name:"terminalTheme",lazy:!0,render:()=>o(l,null,null)}];return(V,t)=>{const _=i;return d(),f(_,{type:"left-bg-card",modelValue:T(e),"onUpdate:modelValue":t[0]||(t[0]=m=>b(e)?e.value=m:null),options:s},null,8,["modelValue"])}}}),R=p(v,[["__scopeId","data-v-9f86e650"]]);export{R as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
