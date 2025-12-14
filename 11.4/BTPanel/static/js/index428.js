import{aD as e,I as a,_ as l}from"./utils-lib.js?v=1765533662";import{c as s,r as t,x as r,O as m,z as o,R as n,e as _,d as u}from"./base-lib.js?v=1765533662";import"./__commonjsHelpers__.js?v=1765533662";const p=l(s({__name:"index",setup(l){const s=u(()=>a(()=>import("./auto-complete.js?v=1765533662"),__vite__mapDeps([]),import.meta.url)),p=u(()=>a(()=>import("./terminal-theme.js?v=1765533662"),__vite__mapDeps([]),import.meta.url)),i=t("smartTips"),d=[{label:"智能提示",lazy:!0,name:"smartTips",render:()=>_(s,null,null)},{label:"终端主题",name:"terminalTheme",lazy:!0,render:()=>_(p,null,null)}];return(a,l)=>{const s=e;return r(),m(s,{type:"left-bg-card",modelValue:o(i),"onUpdate:modelValue":l[0]||(l[0]=e=>n(i)?i.value=e:null),options:d},null,8,["modelValue"])}}}),[["__scopeId","data-v-9f86e650"]]);export{p as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
