# numpy pandas

## numpy as np

### 切片和索引

- 选择行
  - t[2]
  - t[3:,:]
- 选择列
  - t[:,2:]
- 选择行列
  - t[2:5,4,5]
  - t[[2,3,6],[3,5,6]] 选择的是（2，3）（3，5）（，6，6）三个值
- 索引
	- t[2,3]

### 赋值

- t[2,3] = 10

### 布尔索引

- t[t>10] = 1

### 三元运算符

- numpy.where(t>10,1,0) t中大于10的赋值为1，其他赋值0

### 裁剪

- t.clip(10,20) t中小于10的替换为10 大于20的替换为20

### 转置

- t.T
- t.transpose()
- t.swapaxes()

### 从文件读取数据

- numpy.loadtxt(file_path,delimiter,dtype)

### nan inf

- nan 意为不是一个数字 not a number
  - numpy.nan != numpy.nan
  - numpy.count_nonzero(t==t) 获取数组中的非nan个数
  - numpy.isnan(t)
- inf
  - 表示无穷

### 统计函数

- t.sum(axis=0)
- numpy.median(t,axis=0) 中位数
- t.max() t.min()
- numpy.ptp() 极差
- t.std() 标准查 


## Pandas

### Series 一维结构

```python
import pandas as pd
pd.Series(np.arange(8),list('abcdefgh'))
pd.Series({'a':1,'b':2})
```

- Series.index pandas.core.indexes.base.index
- Series.values np.ndarray
- pd.read_csv()
- pd.read_sql(sql_str,db_connect)

### DataFrame 二维结构 Series容器

```python 
import pandas as pd 
pd.DatFrame(numpy.arange(12).reshape((3,4))
```

- df.head(n)
- df.tail(n)
- df.info() 显示列数 行数 字段类型 占用内存
- df.describe() 快速统计数字列的信息
- df.sort_values(by=xxx) 排序
- df[:20] 取前20行
- df['列名'] 取列
- df.loc() 通过标签取行数据
  - df.loc(  )
- df.iloc() 通过位置取行数据
- df[(df['string'].str.len()>4)&(df['int']>10)]
- pd.isnull(df) pd.notnull(df)
- df.dropna(axis=0，how='any',inplace=True) 删除nan存在的一行数据
  - df.dropna(how='all') 删除全部为nan的行数据
- df.fillna(0) df.fillna(df.mean())替换nan
- df.replace('?',np.nan)
- 数组合并
  - df1.join(df2) 按行索引合并 以df1为准 缺失数据为nan
  - df1.merge(df2,on='' how='inner outter right left')
- 数据分组 聚合
  - df.groupby(by='key') 返回值类型
  DataFrameGroup 
  - DataFrameGroup可迭代--->（'key',DataFrame）
  - df.groupby()['key'].count()
  - df.groupby(df[df['key1'],df['key2'] ) 返回复合索引的DataFrame
- 索引 复合索引
  - df.index = [x,x]
  - df.reindex([x,x])
  - df.set_index('a',frop=False) 不删除a列 
  - Series s1['a']['b']
  - DataFrame df1.loc(['a']).loc(['b'])
- 时间序列的处理
  - pd.data_range(start,end,periods个数 freq频率)
  - pd.data_range(start='20140101,end='20140201',freq='10D') 每隔10天
  - pd.to_datatime(df['timeStamp'],format='%')
  - df.resample('M').count()

> 折线图体现变化 散点图体现xy的关系 条形图统计离散数据 直方图统计连续的数据